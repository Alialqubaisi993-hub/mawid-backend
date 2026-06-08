require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "mawid_secret_change_me";

// ─── Supabase ─────────────────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ─── CORS ─────────────────────────────────────────────────────────────────────
app.use(cors({
  origin:"*",
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));
app.use(express.json());

// ─── Health check ─────────────────────────────────────────────────────────────
app.get("/", (req, res) => res.json({ status: "ok", app: "mawid-backend" }));

// ─── Middleware ───────────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) return res.status(401).json({ error: "غير مصرح" });
  try {
    req.user = jwt.verify(auth.split(" ")[1], JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "توكن غير صالح" });
  }
}
function adminOnly(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "للمدير فقط" });
  next();
}
function ownerOnly(req, res, next) {
  if (!["admin", "owner"].includes(req.user.role)) return res.status(403).json({ error: "غير مصرح" });
  next();
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "البريد وكلمة المرور مطلوبان" });

    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .single();

    if (error || !user) return res.status(401).json({ error: "البريد أو كلمة المرور غلط" });
    if (password !== user.password && !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: "البريد أو كلمة المرور غلط" });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    let saloon = null;
    if (user.role === "owner") {
      const { data } = await supabase.from("saloons").select("*").eq("owner_id", user.id).single();
      saloon = data || null;
    }

    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role }, saloon });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "خطأ في الخادم" });
  }
});

// Register (owner)
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, saloonName, activityName, phone, city } = req.body;
    const businessName = activityName || saloonName;
    if (!name || !email || !password || !businessName || !phone)
      return res.status(400).json({ error: "جميع الحقول مطلوبة" });

    const { data: existing } = await supabase.from("users").select("id").eq("email", email).single();
    if (existing) return res.status(400).json({ error: "البريد مسجل مسبقاً" });

    const userId = uuidv4();
    const saloonId = uuidv4();
    const hashedPass = bcrypt.hashSync(password, 10);
    const slug = businessName.trim().replace(/\s+/g, "-") + "-" + saloonId.slice(0, 6);

    const { error: userErr } = await supabase.from("users").insert({
      id: userId, name, email, password: hashedPass, role: "owner",
    });
    if (userErr) throw userErr;

    const { error: saloonErr } = await supabase.from("saloons").insert({
      id: saloonId,
      owner_id: userId,
      name: businessName,
      owner_name: name,
      phone,
      city: city || "",
      status: "pending",
      plan: "free",
      slug,
      bookings_count: 0,
      services: [
        { id: uuidv4(), name: "قص شعر", duration: "30 دقيقة", price: "80" },
        { id: uuidv4(), name: "صبغة شعر", duration: "90 دقيقة", price: "200" },
        { id: uuidv4(), name: "تسريح وبلو", duration: "45 دقيقة", price: "120" },
      ],
      work_days: ["الأحد", "الاثنين", "الثلاثاء", "الأربعاء", "الخميس"],
      time_slots: ["9:00 ص", "9:30 ص", "10:00 ص", "10:30 ص", "11:00 ص", "11:30 ص", "2:00 م", "2:30 م", "3:00 م", "4:00 م", "4:30 م", "5:00 م"],
    });
    if (saloonErr) throw saloonErr;

    res.json({ success: true, message: "تم التسجيل، انتظر موافقة المدير" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "خطأ في التسجيل" });
  }
});

// ─── ADMIN ────────────────────────────────────────────────────────────────────

// جلب كل الصالونات مع إحصائياتها المالية
app.get("/api/admin/saloons", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { data: saloons, error } = await supabase
      .from("saloons")
      .select("*")
      .order("created_at", { ascending: false });
    if (error) throw error;

    // لكل صالون نحسب إجمالي المبالغ من حجوزاته
    const saloonsWithStats = await Promise.all(saloons.map(async (s) => {
      const { data: bookings } = await supabase
        .from("bookings")
        .select("price")
        .eq("saloon_id", s.id)
        .neq("status", "cancelled");

      const bookingCount = bookings?.length || 0;
      const totalAmount = (bookings || []).reduce((sum, b) => sum + (parseFloat(b.price) || 0), 0);

      return {
        ...s,
        bookings: bookingCount,
        totalAmount,
      };
    }));

    res.json(saloonsWithStats);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// إحصائيات عامة مع إجمالي المبالغ
app.get("/api/admin/stats", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { data: saloons } = await supabase.from("saloons").select("status");
    const { data: bookings } = await supabase
      .from("bookings")
      .select("price")
      .neq("status", "cancelled");

    const totalAmount = (bookings || []).reduce((sum, b) => sum + (parseFloat(b.price) || 0), 0);

    res.json({
      total: saloons.length,
      active: saloons.filter(s => s.status === "active").length,
      pending: saloons.filter(s => s.status === "pending").length,
      suspended: saloons.filter(s => s.status === "suspended").length,
      totalBookings: bookings?.length || 0,
      totalAmount,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch("/api/admin/saloons/:id/status", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { status } = req.body;
    const { data, error } = await supabase
      .from("saloons")
      .update({ status })
      .eq("id", req.params.id)
      .select()
      .single();
    if (error) throw error;
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// المدير يعدّل خدمات أي صالون
app.put("/api/admin/saloons/:id/services", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { services } = req.body;
    const { data, error } = await supabase
      .from("saloons")
      .update({ services })
      .eq("id", req.params.id)
      .select()
      .single();
    if (error) throw error;
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// المدير يعدّل أوقات أي صالون
app.put("/api/admin/saloons/:id/timeslots", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { timeSlots, workDays } = req.body;
    const update = {};
    if (timeSlots) update.time_slots = timeSlots;
    if (workDays) update.work_days = workDays;
    const { data, error } = await supabase
      .from("saloons")
      .update(update)
      .eq("id", req.params.id)
      .select()
      .single();
    if (error) throw error;
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── OWNER ────────────────────────────────────────────────────────────────────

app.get("/api/owner/saloon", authMiddleware, ownerOnly, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("saloons")
      .select("*")
      .eq("owner_id", req.user.id)
      .single();
    if (error) return res.status(404).json({ error: "لا يوجد نشاط مرتبط" });
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put("/api/owner/saloon/services", authMiddleware, ownerOnly, async (req, res) => {
  try {
    const { services } = req.body;
    const { data, error } = await supabase
      .from("saloons")
      .update({ services })
      .eq("owner_id", req.user.id)
      .select()
      .single();
    if (error) throw error;
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put("/api/owner/saloon/timeslots", authMiddleware, ownerOnly, async (req, res) => {
  try {
    const { timeSlots, workDays } = req.body;
    const update = {};
    if (timeSlots) update.time_slots = timeSlots;
    if (workDays) update.work_days = workDays;
    const { data, error } = await supabase
      .from("saloons")
      .update(update)
      .eq("owner_id", req.user.id)
      .select()
      .single();
    if (error) throw error;
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/owner/bookings", authMiddleware, ownerOnly, async (req, res) => {
  try {
    const { data: saloon } = await supabase.from("saloons").select("id").eq("owner_id", req.user.id).single();
    if (!saloon) return res.status(404).json({ error: "لا يوجد نشاط" });

    // تصفير يومي: نرجع حجوزات اليوم الحالي فقط (من 12 منتصف الليل)
    const now = new Date();
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 0, 0, 0);

    const { data, error } = await supabase
      .from("bookings")
      .select("*")
      .eq("saloon_id", saloon.id)
      .neq("status", "cancelled")
      .gte("created_at", todayStart.toISOString())
      .order("created_at", { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// تقرير مالي بتواريخ من/إلى
app.get("/api/owner/report", authMiddleware, ownerOnly, async (req, res) => {
  try {
    const { from, to } = req.query;
    const { data: saloon } = await supabase.from("saloons").select("id").eq("owner_id", req.user.id).single();
    if (!saloon) return res.status(404).json({ error: "لا يوجد نشاط" });

    let query = supabase
      .from("bookings")
      .select("*")
      .eq("saloon_id", saloon.id)
      .neq("status", "cancelled")
      .order("created_at", { ascending: false });

    if (from) {
      const fromDate = new Date(from);
      fromDate.setHours(0, 0, 0, 0);
      query = query.gte("created_at", fromDate.toISOString());
    }
    if (to) {
      const toDate = new Date(to);
      toDate.setHours(23, 59, 59, 999);
      query = query.lte("created_at", toDate.toISOString());
    }

    const { data, error } = await query;
    if (error) throw error;

    const totalAmount = (data || []).reduce((sum, b) => sum + (parseFloat(b.price) || 0), 0);
    const totalBookings = data?.length || 0;

    res.json({ bookings: data, totalAmount, totalBookings });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── PUBLIC BOOKING ───────────────────────────────────────────────────────────

app.get("/api/book/:slug", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("saloons")
      .select("id, name, slug, services, work_days, time_slots, status, phone, city")
      .eq("slug", req.params.slug)
      .eq("status", "active")
      .single();
    if (error || !data) return res.status(404).json({ error: "النشاط غير موجود أو غير مفعّل" });
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/book/:slug/booked", async (req, res) => {
  try {
    const { day } = req.query;
    const { data: saloon } = await supabase.from("saloons").select("id, services, time_slots").eq("slug", req.params.slug).single();
    if (!saloon) return res.status(404).json({ error: "غير موجود" });

    const { data: bookings } = await supabase
      .from("bookings")
      .select("time, service")
      .eq("saloon_id", saloon.id)
      .eq("day", day)
      .neq("status", "cancelled");

    // دالة تحويل الوقت العربي لدقائق
    const timeToMinutes = (t) => {
      if (!t) return 0;
      const isAM = t.includes("ص");
      const isPM = t.includes("م");
      const cleaned = t.replace("ص", "").replace("م", "").trim();
      let [h, m] = cleaned.split(":").map(Number);
      if (isPM && h !== 12) h += 12;
      if (isAM && h === 12) h = 0;
      return h * 60 + (m || 0);
    };

    // دالة تحويل الدقائق لوقت عربي
    const minutesToTime = (mins) => {
      const h24 = Math.floor(mins / 60) % 24;
      const m = mins % 60;
      const isAM = h24 < 12;
      const h12 = h24 === 0 ? 12 : h24 > 12 ? h24 - 12 : h24;
      const suffix = isAM ? "ص" : "م";
      return `${h12}:${m.toString().padStart(2, "0")} ${suffix}`;
    };

    // حساب كل الأوقات المحجوزة بما فيها امتداد مدة الخدمة
    const blockedTimes = new Set();
    const timeSlots = saloon.time_slots || [];

    (bookings || []).forEach(b => {
      const svc = (saloon.services || []).find(s => s.name === b.service);
      const durationStr = svc?.duration || "30 دقيقة";
      const durationMins = parseInt(durationStr) || 30;
      const startMins = timeToMinutes(b.time);

      // حجب كل الأوقات اللي تقع ضمن مدة الخدمة
      timeSlots.forEach(slot => {
        const slotMins = timeToMinutes(slot);
        if (slotMins >= startMins && slotMins < startMins + durationMins) {
          blockedTimes.add(slot);
        }
      });
    });

    res.json([...blockedTimes]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/book/:slug", async (req, res) => {
  try {
    const { name, phone, service, day, time } = req.body;
    if (!name || !phone || !service || !day || !time)
      return res.status(400).json({ error: "جميع الحقول مطلوبة" });

    // التحقق من رقم الجوال
    const cleanPhone = phone.replace(/\s+/g, "");
    if (cleanPhone.length < 9)
      return res.status(400).json({ error: "رقم الجوال غير صحيح، أدخل الرقم كاملاً" });

    const { data: saloon } = await supabase
      .from("saloons")
      .select("id, name, services, trial_ends_at, time_slots")
      .eq("slug", req.params.slug)
      .eq("status", "active")
      .single();
    if (!saloon) return res.status(404).json({ error: "النشاط غير موجود" });

    // التحقق من انتهاء الفترة التجريبية
    if (saloon.trial_ends_at && new Date(saloon.trial_ends_at) < new Date()) {
      return res.status(403).json({ error: "انتهت فترة الاشتراك، يرجى التواصل مع مزود الخدمة" });
    }

    // دالة تحويل الوقت العربي لدقائق
    const timeToMins = (t) => {
      if (!t) return 0;
      const isPM = t.includes("م");
      const isAM = t.includes("ص");
      const cleaned = t.replace("ص","").replace("م","").trim();
      let [h, m] = cleaned.split(":").map(Number);
      if (isPM && h !== 12) h += 12;
      if (isAM && h === 12) h = 0;
      return h * 60 + (m || 0);
    };

    // دالة استخراج الدقائق من نص المدة "60 دقيقة" أو "1 ساعة" أو "90"
    const parseDuration = (dur) => {
      if (!dur) return 30;
      const num = parseInt(dur);
      if (isNaN(num)) return 30;
      // إذا كان فيه "ساعة" × 60
      if (dur.includes("ساعة") || dur.includes("ساعه") || dur.includes("hour")) return num * 60;
      return num;
    };

    // استخراج سعر ومدة الخدمة الجديدة
    const svc = (saloon.services || []).find(s => s.name === service);
    const price = svc ? parseFloat(svc.price) || 0 : 0;
    const newDuration = parseDuration(svc?.duration);
    const newStart = timeToMins(time);
    const newEnd = newStart + newDuration;

    // جلب كل حجوزات نفس اليوم
    const { data: dayBookings } = await supabase
      .from("bookings")
      .select("time, service")
      .eq("saloon_id", saloon.id)
      .eq("day", day)
      .neq("status", "cancelled");

    // التحقق من التعارض في الاتجاهين
    const hasConflict = (dayBookings || []).some(b => {
      const existSvc = (saloon.services || []).find(s => s.name === b.service);
      const existDuration = parseDuration(existSvc?.duration);
      const existStart = timeToMins(b.time);
      const existEnd = existStart + existDuration;
      // يتعارض إذا تداخل الوقتان
      return (newStart < existEnd && newEnd > existStart);
    });

    if (hasConflict) return res.status(409).json({ error: "هذا الوقت متعارض مع حجز موجود، الرجاء اختيار وقت آخر" });

    const { data: booking, error } = await supabase.from("bookings").insert({
      id: uuidv4(),
      saloon_id: saloon.id,
      saloon_name: saloon.name,
      name, phone: cleanPhone, service, day, time,
      price,
      status: "confirmed",
    }).select().single();
    if (error) throw error;

    await supabase.rpc("increment_bookings", { saloon_id: saloon.id });

    // إشعار واتساب لصاحب النشاط
    try {
      const { data: saloonFull } = await supabase.from("saloons").select("phone").eq("id", saloon.id).single();
      if (saloonFull?.phone) {
        const ownerPhone = saloonFull.phone.replace(/[^0-9]/g, "");
        const msg = encodeURIComponent(`🔔 حجز جديد في مَوعِد\n👤 ${name}\n📋 ${service}\n📅 ${day} — ${time}\n📞 ${cleanPhone}`);
        const waUrl = `https://api.whatsapp.com/send?phone=${ownerPhone}&text=${msg}`;
        // نحفظ رابط الواتساب في الحجز للمرجعية (اختياري)
        await supabase.from("bookings").update({ whatsapp_url: waUrl }).eq("id", booking.id);
      }
    } catch (waErr) { console.log("WhatsApp notification skipped:", waErr.message); }

    res.json({ success: true, booking });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "خطأ في الحجز" });
  }
});


// ─── ADMIN USERS ──────────────────────────────────────────────────────────────

// جلب كل المستخدمين
app.get("/api/admin/users", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("users")
      .select("id, name, email, role, created_at")
      .order("created_at", { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// إضافة مستخدم جديد
app.post("/api/admin/users", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: "جميع الحقول مطلوبة" });

    const { data: existing } = await supabase.from("users").select("id").eq("email", email).single();
    if (existing) return res.status(400).json({ error: "البريد مسجل مسبقاً" });

    const userId = uuidv4();
    const hashedPass = bcrypt.hashSync(password, 10);

    const { error } = await supabase.from("users").insert({
      id: userId, name, email, password: hashedPass, role: role || "owner",
    });
    if (error) throw error;

    // إذا كان صاحب صالون، أنشئ صالون فارغ له
    if (role === "owner") {
      const saloonId = uuidv4();
      const slug = name.trim().replace(/\s+/g, "-") + "-" + saloonId.slice(0, 6);
      await supabase.from("saloons").insert({
        id: saloonId, owner_id: userId, name: name + " نشاط",
        owner_name: name, phone: "", city: "", status: "pending",
        plan: "free", slug, bookings_count: 0, services: [], work_days: [], time_slots: [],
      });
    }

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// حذف مستخدم
app.delete("/api/admin/users/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { error } = await supabase.from("users").delete().eq("id", req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// تغيير كلمة المرور
app.patch("/api/admin/users/:id/password", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: "كلمة المرور مطلوبة" });
    const hashedPass = bcrypt.hashSync(password, 10);
    const { error } = await supabase.from("users").update({ password: hashedPass }).eq("id", req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});



// ─── ADMIN BOOKINGS ───────────────────────────────────────────────────────────

// المدير يشوف كل الحجوزات من كل الأنشطة
app.get("/api/admin/bookings", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { from, to, saloon_id } = req.query;

    let query = supabase
      .from("bookings")
      .select("*")
      .neq("status", "cancelled")
      .order("created_at", { ascending: false });

    if (saloon_id) query = query.eq("saloon_id", saloon_id);

    if (from) {
      const fromDate = new Date(from);
      fromDate.setHours(0, 0, 0, 0);
      query = query.gte("created_at", fromDate.toISOString());
    }
    if (to) {
      const toDate = new Date(to);
      toDate.setHours(23, 59, 59, 999);
      query = query.lte("created_at", toDate.toISOString());
    }

    const { data, error } = await query;
    if (error) throw error;

    const totalAmount = (data || []).reduce((sum, b) => sum + (parseFloat(b.price) || 0), 0);
    res.json({ bookings: data, totalAmount, totalBookings: data?.length || 0 });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── ADMIN TRIAL ──────────────────────────────────────────────────────────────

// تحديث فترة الاشتراك
app.patch("/api/admin/saloons/:id/trial", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { trial_starts_at, trial_ends_at } = req.body;
    const update = {};
    if (trial_starts_at) update.trial_starts_at = trial_starts_at;
    if (trial_ends_at) update.trial_ends_at = trial_ends_at;
    const { data, error } = await supabase
      .from("saloons")
      .update(update)
      .eq("id", req.params.id)
      .select()
      .single();
    if (error) throw error;
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


// إلغاء موعد من صاحب النشاط
app.patch("/api/owner/bookings/:id/cancel", authMiddleware, ownerOnly, async (req, res) => {
  try {
    const { reason } = req.body;
    // تحقق إن الحجز يخص صالون صاحب النشاط
    const { data: saloon } = await supabase.from("saloons").select("id").eq("owner_id", req.user.id).single();
    if (!saloon) return res.status(404).json({ error: "لا يوجد نشاط" });

    const { data: booking, error } = await supabase
      .from("bookings")
      .update({ status: "cancelled", cancel_reason: reason || "اعتذار من صاحب النشاط" })
      .eq("id", req.params.id)
      .eq("saloon_id", saloon.id)
      .select()
      .single();
    if (error) throw error;

    res.json({ success: true, booking });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── IMAGE UPLOAD ─────────────────────────────────────────────────────────────

// رفع صورة خدمة لـ Supabase Storage
app.post("/api/owner/upload-image", authMiddleware, ownerOnly, express.raw({ type: "*/*", limit: "10mb" }), async (req, res) => {
  try {
    const contentType = req.headers["content-type"] || "image/jpeg";
    const ext = contentType.includes("png") ? "png" : contentType.includes("gif") ? "gif" : contentType.includes("webp") ? "webp" : "jpg";
    const fileName = `service-${uuidv4()}.${ext}`;
    const buffer = req.body;

    console.log("Upload attempt:", { contentType, fileName, bufferSize: buffer?.length });

    if (!buffer || buffer.length === 0) return res.status(400).json({ error: "لا توجد صورة" });

    const { data, error } = await supabase.storage
      .from("services")
      .upload(fileName, buffer, { contentType, upsert: false });

    if (error) {
      console.error("Supabase storage error:", error);
      throw error;
    }

    const { data: urlData } = supabase.storage
      .from("services")
      .getPublicUrl(fileName);

    console.log("Upload success:", urlData.publicUrl);
    res.json({ url: urlData.publicUrl });
  } catch (e) {
    console.error("Upload error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ─── START ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`✅ Mawid Backend on port ${PORT}`));
