// फाइल: api/handler.js
const { MongoClient } = require('mongodb');

// ===================================================================================
// ===== আপনার সকল তথ্য এখানে পূরণ করুন =====
// ===================================================================================
const MONGODB_URI = "mongodb+srv://mesohas358:mesohas358@cluster0.6kxy1vc.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
const ADMIN_PASSWORD = "123";
// ===================================================================================

export default async function handler(req, res) {
    if (req.method === 'GET') {
        return await handleApiGet(req, res);
    }
    if (req.method === 'POST') {
        return await handleApiPost(req, res);
    }
    return res.status(405).json({ message: 'Method Not Allowed' });
}

async function handleApiGet(req, res) {
    const { id } = req.query;
    if (!id) return res.status(400).json({ message: "ID is required" });

    const client = new MongoClient(MONGODB_URI);
    try {
        await client.connect();
        const dbName = new URL(MONGODB_URI).pathname.substring(1) || 'linkApp';
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
    const { title, links, password } = req.body;

    if (password !== ADMIN_PASSWORD) {
        return res.status(401).json({ message: 'Unauthorized: Invalid Password' });
    }

    const client = new MongoClient(MONGODB_URI);
    try {
        await client.connect();
        const dbName = new URL(MONGODB_URI).pathname.substring(1) || 'linkApp';
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
