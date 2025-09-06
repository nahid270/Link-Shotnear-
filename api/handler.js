// ফাইল: api/handler.js
const { MongoClient } = require('mongodb');

// ===================================================================================
// ===== আপনার সকল তথ্য এখানে পূরণ করুন =====
// ===================================================================================

// আপনার MongoDB Atlas কানেকশন স্ট্রিংটি এখানে পেস্ট করুন।
// URI-এর মধ্যে অবশ্যই আপনার ডাটাবেসের নামটি উল্লেখ করুন (নিচের উদাহরণ দেখুন)।
const MONGODB_URI = "mongodb+srv://mesohas358:mesohas358@cluster0.6kxy1vc.mongodb.net/আপনার_ডাটাবেসের_নাম?retryWrites=true&w=majority&appName=Cluster0";

// আপনার অ্যাডমিন প্যানেলের জন্য একটি শক্তিশালী পাসওয়ার্ড এখানে দিন।
// অনুগ্রহ করে "123" এর বদলে আরও কঠিন কিছু ব্যবহার করুন।
const ADMIN_PASSWORD = "আপনার_শক্তিশালী_পাসওয়ার্ড";

// ===================================================================================
// ===== কোডের এই অংশের নিচে কিছু পরিবর্তন করার প্রয়োজন নেই =====
// ===================================================================================

async function mainHandler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    if (req.method === 'GET' && req.query.id) {
        return await handleApiGet(req, res);
    }
    if (req.method === 'POST') {
        return await handleApiPost(req, res);
    }
    return res.status(200).send(getHtmlPage());
}

async function handleApiGet(req, res) {
    const { id } = req.query;
    if (!id) return res.status(400).json({ message: "ID is required" });

    const client = new MongoClient(MONGODB_URI);
    try {
        await client.connect();
        const dbName = new URL(MONGODB_URI).pathname.substring(1);
        const collection = client.db(dbName).collection("entries");
        const entry = await collection.findOne({ shortId: id });
        if (!entry) return res.status(404).json({ message: 'Link Not Found' });
        return res.status(200).json(entry);
    } catch (error) {
        console.error("API GET Error:", error);
        return res.status(500).json({ message: 'Internal Server Error' });
    } finally {
        await client.close();
    }
}

async function handleApiPost(req, res) {
    const body = await parseJsonBody(req);
    const { title, links, password } = body;

    if (password !== ADMIN_PASSWORD) {
        return res.status(401).json({ message: 'Unauthorized: Invalid Password' });
    }
    
    const client = new MongoClient(MONGODB_URI);
    try {
        await client.connect();
        const dbName = new URL(MONGODB_URI).pathname.substring(1);
        const collection = client.db(dbName).collection("entries");
        const newEntry = {
            shortId: Math.random().toString(36).substring(2, 8),
            title,
            links,
            createdAt: new Date(),
        };
        await collection.insertOne(newEntry);
        return res.status(201).json(newEntry);
    } catch (error) {
        console.error("API POST Error:", error);
        return res.status(500).json({ message: 'Internal Server Error' });
    } finally {
        await client.close();
    }
}

function parseJsonBody(req) {
    return new Promise((resolve) => {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', () => resolve(JSON.parse(body || '{}')));
    });
}

function getHtmlPage() {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Link Protector</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root{ --bg:#f3f5f8; --card:#ffffff; --ink:#0f172a; --muted:#64748b; --ring:#dbe3ef; --shadow:0 10px 30px rgba(2,6,23,.08); --blue:#2563eb; --green:#16a3a; --red: #ef4444; }
        body { font-family: 'Inter', sans-serif; background: var(--bg); color: var(--ink); margin: 0; padding: 24px; display: flex; justify-content: center; align-items: flex-start; min-height: 100vh; }
        .container { max-width: 800px; width: 100%; }
        .card { background: var(--card); border: 1px solid var(--ring); border-radius: 20px; padding: 24px; margin-top: 20px; box-shadow: var(--shadow); }
        h1 { text-align: center; color: var(--ink); }
        input, button { font-family: inherit; font-size: 16px; padding: 12px; border-radius: 10px; border: 1px solid var(--ring); width: 100%; box-sizing: border-box; margin-bottom: 12px; }
        button { background: var(--blue); color: #fff; font-weight: 700; cursor: pointer; border: none; transition: background-color 0.2s; }
        button:hover { background-color: #1d4ed8; }
        button:disabled { background-color: var(--muted); cursor: not-allowed; }
        button.secondary { background-color: var(--green); }
        button.secondary:hover { background-color: #15803d; }
        button.remove-btn { background-color: var(--red); width: auto; padding: 0 12px; margin-left: 10px; }
        .hidden { display: none; }
        #links-container .link-entry { display: flex; gap: 10px; align-items: center; margin-bottom: 8px; }
        #links-container input { flex-grow: 1; margin-bottom: 0; }
        .link-btn{display:flex;align-items:center;justify-content:space-between;padding:16px 18px;border-radius:16px;color:#fff;font-weight:800;background:var(--blue); text-decoration: none; margin-bottom: 12px;}
        .message { text-align: center; font-weight: bold; margin-top: 15px; padding: 10px; border-radius: 8px; }
        .success { color: var(--green); background-color: #f0fdf4; }
        .error { color: var(--red); background-color: #fef2f2; }
    </style>
</head>
<body>
<div class="container">
    <div id="viewSection" class="hidden">
        <div class="card">
            <h1 id="viewTitle">Loading...</h1>
            <div id="unlockBox"><button id="unlockBtn" disabled>Please wait (5s)</button></div>
            <div id="linksGrid" class="hidden"></div>
        </div>
    </div>
    <div id="adminSection" class="hidden">
        <div class="card">
            <h1>Admin Panel</h1>
            <input type="text" id="title" placeholder="Enter Title (e.g., Movie Name)">
            <div id="links-container"></div>
            <button class="secondary" onclick="addLinkField()">+ Add Link Format</button>
            <input type="password" id="adminPassword" placeholder="Admin Password">
            <button id="createBtn" onclick="submitLinks()">Create Sharable Link</button>
            <div id="adminMessage" class="message"></div>
        </div>
    </div>
</div>
<script>
    const API_ENDPOINT = window.location.origin + window.location.pathname;

    function init() {
        const params = new URLSearchParams(window.location.search);
        const viewId = params.get('id');
        if (viewId) {
            document.getElementById('viewSection').classList.remove('hidden');
            loadLinkForView(viewId);
        } else {
            document.getElementById('adminSection').classList.remove('hidden');
            addLinkField();
        }
    }

    async function loadLinkForView(id) {
        try {
            const res = await fetch(\`\${API_ENDPOINT}?id=\${id}\`);
            if (!res.ok) throw new Error('Link not found or expired!');
            const data = await res.json();
            document.title = data.title;
            document.getElementById('viewTitle').textContent = data.title;
            let wait = 5;
            const unlockBtn = document.getElementById('unlockBtn');
            const timer = setInterval(() => {
                unlockBtn.textContent = \`Unlock Links (\${wait--}s)\`;
                if (wait < 0) {
                    clearInterval(timer);
                    unlockBtn.textContent = 'Click to Unlock';
                    unlockBtn.disabled = false;
                    unlockBtn.onclick = () => showLinks(data.links);
                }
            }, 1000);
        } catch (error) {
            document.getElementById('viewTitle').textContent = error.message;
            document.getElementById('unlockBox').classList.add('hidden');
        }
    }

    function showLinks(links) {
        document.getElementById('unlockBox').classList.add('hidden');
        const linksGrid = document.getElementById('linksGrid');
        linksGrid.innerHTML = '';
        if (links && links.length > 0) {
            links.forEach(link => {
                const a = document.createElement('a');
                a.className = 'link-btn';
                a.href = link.url;
                a.target = '_blank';
                a.rel = 'noopener noreferrer';
                a.textContent = link.label;
                linksGrid.appendChild(a);
            });
        } else {
            linksGrid.textContent = "No links available for this entry.";
        }
        linksGrid.classList.remove('hidden');
    }

    function addLinkField() {
        const container = document.getElementById('links-container');
        const entry = document.createElement('div');
        entry.className = 'link-entry';
        entry.innerHTML = \`<input type="text" class="linkLabel" placeholder="Label (e.g., 1080p Gofile)"><input type="url" class="linkUrl" placeholder="https://example.com/link"><button class="remove-btn" onclick="this.parentElement.remove()">X</button>\`;
        container.appendChild(entry);
    }

    async function submitLinks() {
        const createBtn = document.getElementById('createBtn');
        const title = document.getElementById('title').value;
        const password = document.getElementById('adminPassword').value;
        const linkEntries = document.querySelectorAll('.link-entry');
        const adminMessage = document.getElementById('adminMessage');
        adminMessage.textContent = '';
        adminMessage.className = 'message';
        const links = Array.from(linkEntries).map(entry => ({
            label: entry.querySelector('.linkLabel').value.trim(),
            url: entry.querySelector('.linkUrl').value.trim()
        })).filter(l => l.label && l.url);
        if (!title || links.length === 0 || !password) {
            adminMessage.textContent = 'Please fill title, password, and at least one link format.';
            adminMessage.classList.add('error');
            return;
        }
        createBtn.disabled = true;
        createBtn.textContent = 'Creating...';
        adminMessage.textContent = 'Please wait...';
        try {
            const res = await fetch(API_ENDPOINT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ title, links, password }),
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.message || 'Failed to create link.');
            const shareableLink = \`\${API_ENDPOINT}?id=\${data.shortId}\`;
            adminMessage.innerHTML = \`Success! Share this link: <br><input type="text" value="\${shareableLink}" readonly onclick="this.select()">\`;
            adminMessage.classList.add('success');
        } catch (error) {
            adminMessage.textContent = \`Error: \${error.message}\`;
            adminMessage.classList.add('error');
        } finally {
            createBtn.disabled = false;
            createBtn.textContent = 'Create Sharable Link';
        }
    }
    document.addEventListener('DOMContentLoaded', init);
</script>
</body>
</html>`;
}

module.exports = mainHandler;
