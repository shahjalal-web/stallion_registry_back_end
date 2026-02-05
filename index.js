const express = require("express");
const cors = require("cors");
require("dotenv").config();
const app = express();
const PORT = process.env.PORT || 5000;
// Middleware setup
app.use(cors());
app.use(express.json());

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const { verifyJWT, verifyAdmin } = require("./middleware");

app.get("/", async (req, res) => {
  res.send("stallion server is running on port 5000");
});

const uri =
  "mongodb+srv://stallionRegistry:stallionRegistry@cluster0.xnyro57.mongodb.net/?appName=Cluster0";

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    const userCollection = client.db("stallion").collection("user");
    const stallionCollection = client.db("stallion").collection("stallions");

    app.get("/stallions/:id", async (req, res) => {
      console.log("Requested ID:", req.params.id); // ADD

      const stallion = await stallionCollection.findOne({
        _id: new ObjectId(req.params.id),
      });

      console.log("Found:", stallion); // ADD

      if (!stallion) return res.status(404).send({ message: "Not found" });

      res.send(stallion);
    });

    app.delete("/stallions/:id", verifyJWT, async (req, res) => {
      try {
        const stallionId = new ObjectId(req.params.id);

        const stallion = await stallionCollection.findOne({ _id: stallionId });
        if (!stallion) return res.status(404).send({ message: "Not found" });

        // 🔐 নিশ্চিত করবো stallion টা তার নিজের
        if (stallion.owner.userId.toString() !== req.user.userId) {
          return res.status(403).send({ message: "Not allowed" });
        }

        // 🐎 Delete stallion
        await stallionCollection.deleteOne({ _id: stallionId });

        // 👤 User doc update
        await userCollection.updateOne(
          { _id: new ObjectId(req.user.userId) },
          { $pull: { registeredStallions: stallionId } },
        );

        res.send({ message: "Stallion deleted" });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Delete failed" });
      }
    });

    app.get("/my-stallions", verifyJWT, async (req, res) => {
  try {
    const userId = new ObjectId(req.user.userId);

    const stallions = await stallionCollection
      .find({ "owner.userId": userId })
      .toArray();

    res.send(stallions);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to fetch stallions" });
  }
});


    app.post("/admin/login", async (req, res) => {
      const { email, password } = req.body;

      const admin = await userCollection.findOne({ email, role: "admin" });
      if (!admin) return res.status(401).send({ message: "Not authorized" });

      const isMatch = await bcrypt.compare(password, admin.password);
      if (!isMatch)
        return res.status(401).send({ message: "Invalid credentials" });

      const token = jwt.sign(
        { userId: admin._id, role: "admin" },
        process.env.JWT_SECRET,
        { expiresIn: "7d" },
      );

      const { password: _, ...adminWithoutPass } = admin;

      res.send({ admin: adminWithoutPass, token });
    });

    app.post("/signup", async (req, res) => {
      try {
        const { name, email, password, ...rest } = req.body;
        // 1️⃣ Email already আছে কিনা check
        const existingUser = await userCollection.findOne({ email });
        if (existingUser) {
          return res.status(400).send({ message: "Email already exists" });
        }

        // 2️⃣ Password hash
        const hashedPassword = await bcrypt.hash(password, 10);

        // 3️⃣ User object তৈরি (role force করে দিচ্ছি)
        const newUser = {
          name,
          email,
          password: hashedPassword,
          role: "user", // 🔥 default role
          createdAt: new Date(),
          ...rest,
        };

        // 4️⃣ DB তে save
        const result = await userCollection.insertOne(newUser);
        const token = jwt.sign(
          { userId: result.insertedId, email, role: "user" },
          process.env.JWT_SECRET,
          { expiresIn: "7d" },
        );

        const savedUser = await userCollection.findOne(
          { _id: result.insertedId },
          { projection: { password: 0 } },
        );

        res.send({
          message: "Signup successful",
          user: savedUser,
          token,
        });
      } catch (error) {
        res.status(500).send({ message: "Server error" });
      }
    });

    app.post("/login", async (req, res) => {
      try {
        const { email, password } = req.body;

        const user = await userCollection.findOne({ email });
        if (!user) {
          return res.status(400).send({ message: "Invalid email or password" });
        }

        // 🔐 Compare hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          return res.status(400).send({ message: "Invalid email or password" });
        }

        // 🎟️ Create JWT
        const token = jwt.sign(
          {
            userId: user._id,
            email: user.email,
            role: user.role,
          },
          process.env.JWT_SECRET,
          { expiresIn: "7d" },
        );

        // 🚫 password বাদ দিয়ে user পাঠানো
        const { password: _, ...userWithoutPassword } = user;

        res.send({
          message: "Login successful",
          user: userWithoutPassword,
          token,
        });
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Server error" });
      }
    });

    app.post("/stallions", verifyJWT, async (req, res) => {
      try {
        const stallionData = req.body;
        console.log("hello");
        // 🔎 Logged in user find
        const user = await userCollection.findOne({
          _id: new ObjectId(req.user.userId),
        });

        if (!user) return res.status(404).send({ message: "User not found" });

        const newStallion = {
          ...stallionData,
          owner: {
            userId: user._id,
            name: user.name,
            email: user.email,
          },
          submittedAt: new Date(),
        };

        // 🐎 Save stallion
        const result = await stallionCollection.insertOne(newStallion);

        // 👤 Update user → registeredStallions
        await userCollection.updateOne(
          { _id: user._id },
          { $push: { registeredStallions: result.insertedId } },
        );

        res.send({ message: "Stallion submitted", id: result.insertedId });
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Server error" });
      }
    });

    app.get("/stallions", async (req, res) => {
      try {
        const stallions = await stallionCollection.find({}).toArray();

        res.send(stallions);
      } catch (err) {
        res.status(500).send({ message: "Failed to fetch stallions" });
      }
    });

    app.patch(
      "/admin/stallions/approve/:id",
      verifyAdmin(userCollection),
      async (req, res) => {
        try {
          const stallion = await stallionCollection.findOne({
            _id: new ObjectId(req.params.id),
          });

          if (!stallion) return res.status(404).send({ message: "Not found" });

          await stallionCollection.updateOne(
            { _id: stallion._id },
            { $set: { approved: !stallion.approved } },
          );

          res.send({ message: "Approval status updated" });
        } catch {
          res.status(500).send({ message: "Update failed" });
        }
      },
    );

    app.get("/admin/users", verifyAdmin(userCollection), async (req, res) => {
      try {
        const users = await userCollection
          .find({ _id: { $ne: new ObjectId(req.user.userId) } })
          .project({ password: 0 })
          .toArray();

        res.send(users);
      } catch (err) {
        res.status(500).send({ message: "Failed to fetch users" });
      }
    });

    app.delete(
      "/admin/users/:id",
      verifyAdmin(userCollection),
      async (req, res) => {
        try {
          await userCollection.deleteOne({ _id: new ObjectId(req.params.id) });
          res.send({ message: "User deleted" });
        } catch {
          res.status(500).send({ message: "Delete failed" });
        }
      },
    );

    app.get(
      "/admin/stallions",
      verifyAdmin(userCollection),
      async (req, res) => {
        try {
          const stallions = await stallionCollection.find({}).toArray();
          res.send(stallions);
        } catch (err) {
          res.status(500).send({ message: "Failed to fetch stallions" });
        }
      },
    );

    app.delete(
      "/admin/stallions/:id",
      verifyAdmin(userCollection),
      async (req, res) => {
        try {
          const stallionId = new ObjectId(req.params.id);

          // 🐎 Stallion delete
          const stallion = await stallionCollection.findOne({
            _id: stallionId,
          });
          if (!stallion) {
            return res.status(404).send({ message: "Stallion not found" });
          }

          await stallionCollection.deleteOne({ _id: stallionId });

          // 👤 Remove from user's registeredStallions array
          await userCollection.updateOne(
            { _id: new ObjectId(stallion.owner.userId) },
            { $pull: { registeredStallions: stallionId } },
          );

          res.send({ message: "Stallion deleted & user updated" });
        } catch (err) {
          console.error(err);
          res.status(500).send({ message: "Delete failed" });
        }
      },
    );

    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!",
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}

run().catch(console.dir);

app.listen(PORT, () => {
  console.log(`stallion server is runnig on port : ${PORT}`);
});
