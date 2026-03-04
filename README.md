# 🌸 Bloom — Real-Time Messaging App

A beautiful, romantic real-time messaging app. No Firebase, no cloud needed — runs entirely on your machine.

## ✨ Features

- 🔐 Accounts with username & password (stored locally)
- 💬 Real-time messaging via Socket.io
- 👤 Direct messages — find people by username
- 👥 Group chats with any number of members  
- 🖼️ Send images and videos (up to 50MB)
- ✏️ Edit your own messages
- 🗑️ Delete your own messages
- 🌸 Name-based particle effects (زهور = falling cherry blossoms, etc.)
- 📱 Fully mobile-friendly
- 💾 All data saved in a local SQLite database file (`bloom.db`)
- 🟢 Online presence indicators
- ⌨️ Typing indicators

## 🚀 Setup (takes 2 minutes)

### Requirements
- [Node.js](https://nodejs.org) — version 16 or newer

### Steps

1. **Extract** the bloom folder somewhere on your computer

2. **Open a terminal** in the bloom folder

3. **Install dependencies:**
   ```
   npm install
   ```

4. **Start the server:**
   ```
   npm start
   ```

5. **Open in browser:**
   ```
   http://localhost:3000
   ```

That's it! Create an account and start messaging.

---

## 👥 Multi-user / Multi-device

To use across multiple devices on the **same WiFi network**:

1. Find your computer's local IP (e.g. `192.168.1.5`)  
   - Mac/Linux: `ifconfig` or `ip addr`
   - Windows: `ipconfig`

2. Other devices open: `http://192.168.1.5:3000`

For access over the internet, use a free tunnel like [ngrok](https://ngrok.com):
```
npx ngrok http 3000
```
Then share the ngrok URL with anyone!

---

## 📁 File Structure

```
bloom/
├── server.js          ← Node.js backend (Express + Socket.io + SQLite)
├── package.json
├── bloom.db           ← Created automatically on first run (your data lives here)
├── uploads/           ← Created automatically for media files
└── public/
    └── index.html     ← The entire frontend
```

## 🌸 Name Effects

When you create your account, your name determines the falling particle effect:

| Name | Effect |
|------|--------|
| زهور | 🌸 Cherry blossoms |
| ورد | 🌹 Roses |
| ياسمين | 🌼 Jasmine |
| نور | ✨ Sparkles |
| سمر | 🌙 Moons |
| لمى | 💜 Hearts |
| ريم | 🦋 Butterflies |
| دانا | 💎 Diamonds |
| luna | 🌙 Moons |
| rose | 🌹 Roses |
| nova | 💫 Stars |
| Any other name | 💕 Hearts |
