require('dotenv').config();
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('../src/modules/users/user.model');

const csvPath = process.argv[2] || path.join(__dirname, '..', 'users_seed.csv');

const parseCsv = (text) => {
  const lines = text.split(/\r?\n/).filter(Boolean);
  if (!lines.length) return [];
  const rows = [];
  for (let i = 1; i < lines.length; i += 1) {
    const parts = lines[i].split(',');
    if (parts.length < 4) continue;
    const [name, email, role, password] = parts.map((p) => p.trim());
    if (!email || !role || !password) continue;
    rows.push({ name, email, role, password });
  }
  return rows;
};

(async () => {
  if (!process.env.MONGO_URI) {
    throw new Error('MONGO_URI is not set');
  }

  const csv = fs.readFileSync(csvPath, 'utf-8');
  const users = parseCsv(csv);
  if (!users.length) {
    console.log('No users found in CSV.');
    return;
  }

  await mongoose.connect(process.env.MONGO_URI);

  let upserted = 0;
  for (const u of users) {
    const email = u.email.toLowerCase();
    const passwordHash = await bcrypt.hash(u.password, 10);
    const res = await User.updateOne(
      { email },
      {
        $set: {
          name: u.name,
          email,
          role: u.role,
          passwordHash,
        },
      },
      { upsert: true }
    );

    if (res.upsertedCount) upserted += 1;
  }

  console.log(`Seed complete. Users processed: ${users.length}. New users: ${upserted}.`);
  await mongoose.disconnect();
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
