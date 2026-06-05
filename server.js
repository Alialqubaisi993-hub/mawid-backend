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
    const { name, email, password, saloonName, phone, city } = req.body;
    if (!name || !email || !password || !saloonName || !phone)
      return res.status(400).json({ error: "جميع الحقول مطلوبة" });

    const { data: existing } = await supabase.from("users").select("id").eq("email", email).single();
    if (existing) return res.status(400).json({ error: "البريد مسجل مسبقاً" });

    const userId = uuidv4();
    const saloonId = uuidv4();
    const hashedPass = bcrypt.hashSync(password, 10);
    const slug = saloonName.trim().replace(/\s+/g, "-") + "-" + saloonId.slice(0, 6);

    const { error: userErr } = await supabase.from("users").insert({
      id: userId,
      name,
      email,
      password: hashedPass,
      role: "owner",
    });
    if (userErr) throw userErr;

    const { error: saloonErr } = await supabase.from("saloons").insert({
      id: saloonId,
      owner_id: userId,
      name: saloonName,
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

app.get("/api/admin/saloons", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase.from("saloons").select("*").order("created_at", { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/admin/stats", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { data: saloons } = await supabase.from("saloons").select("status, bookings_count");
    const { count: totalBookings } = await supabase.from("bookings").select("id", { count: "exact", head: true });
    res.json({
      total: saloons.length,
      active: saloons.filter(s => s.status === "active").length,
      pending: saloons.filter(s => s.status === "pending").length,
      suspended: saloons.filter(s => s.status === "suspended").length,
      totalBookings: totalBookings || 0,
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

// ─── OWNER ────────────────────────────────────────────────────────────────────

app.get("/api/owner/saloon", authMiddleware, ownerOnly, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("saloons")
      .select("*")
      .eq("owner_id", req.user.id)
      .single();
    if (error) return res.status(404).json({ error: "لا يوجد صالون مرتبط" });
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
    if (!saloon) return res.status(404).json({ error: "لا يوجد صالون" });
    const { data, error } = await supabase
      .from("bookings")
      .select("*")
      .eq("saloon_id", saloon.id)
      .neq("status", "cancelled")
      .order("created_at", { ascending: false });
    if (error) throw error;
    res.json(data);
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
    if (error || !data) return res.status(404).json({ error: "الصالون غير موجود أو غير مفعّل" });
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/book/:slug/booked", async (req, res) => {
  try {
    const { day } = req.query;
    const { data: saloon } = await supabase.from("saloons").select("id").eq("slug", req.params.slug).single();
    if (!saloon) return res.status(404).json({ error: "غير موجود" });
    const { data } = await supabase
      .from("bookings")
      .select("time")
      .eq("saloon_id", saloon.id)
      .eq("day", day)
      .neq("status", "cancelled");
    res.json((data || []).map(b => b.time));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/book/:slug", async (req, res) => {
  try {
    const { name, phone, service, day, time } = req.body;
    if (!name || !phone || !service || !day || !time)
      return res.status(400).json({ error: "جميع الحقول مطلوبة" });

    const { data: saloon } = await supabase
      .from("saloons")
      .select("id, name")
      .eq("slug", req.params.slug)
      .eq("status", "active")
      .single();
    if (!saloon) return res.status(404).json({ error: "الصالون غير موجود" });

    const { data: taken } = await supabase
      .from("bookings")
      .select("id")
      .eq("saloon_id", saloon.id)
      .eq("day", day)
      .eq("time", time)
      .neq("status", "cancelled")
      .single();
    if (taken) return res.status(409).json({ error: "هذا الوقت محجوز مسبقاً" });

    const { data: booking, error } = await supabase.from("bookings").insert({
      id: uuidv4(),
      saloon_id: saloon.id,
      saloon_name: saloon.name,
      name,
      phone,
      service,
      day,
      time,
      status: "confirmed",
    }).select().single();
    if (error) throw error;

    // increment bookings count
    await supabase.rpc("increment_bookings", { saloon_id: saloon.id });

    res.json({ success: true, booking });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "خطأ في الحجز" });
  }
});

// ─── START ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`✅ Mawid Backend on port ${PORT}`));
