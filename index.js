const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes } = require('sequelize');
const bcrypt = require('bcrypt');


const app = express();
const port = 3000;

// Configure body-parser and multer for handling form data
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
const upload = multer({ dest: 'uploads/' });

// Secret key for JWT
const secretKey = 'ayomide-adegoke-adeleke';

// Connect to SQLite database
const dbFilePath = path.join(__dirname, 'database.sqlite');

const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: dbFilePath,
});


// Define User model
const User = sequelize.define('User', {
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  profilePicture: {
    type: DataTypes.STRING,
    defaultValue: 'default.jpg',
  },
});

// Define Group model
const Group = sequelize.define('Group', {
  name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

// Define Message model
const Message = sequelize.define('Message', {
  message: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  file: {
    type: DataTypes.STRING,
  },
});

// Define associations
User.hasMany(Message, { foreignKey: 'senderId' });
Message.belongsTo(User, { foreignKey: 'senderId' });
Group.hasMany(Message, { foreignKey: 'groupId' });
Message.belongsTo(Group, { foreignKey: 'groupId' });
User.hasMany(Group, { foreignKey: 'ownerId' });
Group.belongsTo(User, { foreignKey: 'ownerId' });


// Middleware for user authentication
async function authenticateUser(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    
    const decoded = jwt.verify(token, secretKey);
    console.log(`decoded ${JSON.stringify(decoded)}`)
    const user = await User.findOne({ where: { username: decoded.username } });
    if (!user) {
      return res.status(401).json({ message: 'Invalid tokens' });
    }
    req.user = user;
    next();
  } catch (err) {
    console.log(err)
    return res.status(401).json({ message: 'Invalid token' });
  }
}

// Sync models with the database
sequelize.sync().then(() => {
  console.log('Database synchronized');
}).catch((err) => {
  console.error('Failed to synchronize database:', err);
});

// Get all users endpoint
app.get('/', (req, res) => {
  res.json("Chat API IS LIVE");
});

// User registration endpoint
// User registration endpoint
app.post('/register', upload.single('profilePicture'), async (req, res) => {
  const { username, password } = req.body;
  const profilePicture = req.file ? req.file.filename : 'default.jpg'; // Use default image if no profile picture is uploaded

  try {
    const hashedPassword = await bcrypt.hash(password, 10); // Hash the password with bcrypt
    const user = await User.create({ username, password: hashedPassword, profilePicture });
    res.json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Error occurred while registering user:', err);
    res.status(500).json({ message: 'Error occurred while registering user' });
  }
});

// Get all users endpoint
app.get('/users', async (req, res) => {
  try {
    const users = await User.findAll();
    res.json(users);
  } catch (err) {
    console.error('Error occurred while retrieving users:', err);
    res.status(500).json({ message: 'Error occurred while retrieving users' });
  }
});

// Update user information endpoint
app.put('/user', authenticateUser, upload.single('profilePicture'), async (req, res) => {
  const { username } = req.user;
  const profilePicture = req.file ? req.file.filename : req.user.profilePicture; // Use existing profile picture if no new picture is uploaded

  try {
    const user = await User.update({ profilePicture }, { where: { username } });
    res.json({ message: 'User information updated successfully' });
  } catch (err) {
    console.error('Error occurred while updating user information:', err);
    res.status(500).json({ message: 'Error occurred while updating user information' });
  }
});

// User login endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ where: { username } });
    if (!user) {
      res.status(401).json({ message: 'Invalid username or password' });
    } else {
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (passwordMatch) {
        const token = jwt.sign({ username }, secretKey, { expiresIn: '1h' });
        res.json({ token });
      } else {
        res.status(401).json({ message: 'Invalid username or password' });
      }
    }
  } catch (err) {
    console.error('Error occurred while logging in:', err);
    res.status(500).json({ message: 'Error occurred while logging in' });
  }
});


// One-to-one chat endpoint
app.post('/chat/one-to-one', authenticateUser, async (req, res) => {
  const { recipient, message } = req.body;
  const sender = req.user.username;

  try {
    const senderUser = await User.findOne({ where: { username: sender } });
    const recipientUser = await User.findOne({ where: { username: recipient } });
    if (!senderUser || !recipientUser) {
      res.status(404).json({ message: 'Sender or recipient not found' });
    } else {
      const msg = await Message.create({ senderId: senderUser.id, message });
      res.json({ message: 'Message sent successfully' });
    }
  } catch (err) {
    console.error('Error occurred while sending message:', err);
    res.status(500).json({ message: 'Error occurred while sending message' });
  }
});

// One-to-many chat endpoint
app.post('/chat/one-to-many', authenticateUser, async (req, res) => {
  const { recipients, message } = req.body;
  const sender = req.user.username;

  try {
    const senderUser = await User.findOne({ where: { username: sender } });
    if (!senderUser) {
      res.status(404).json({ message: 'Sender not found' });
    } else {
      const recipientUsers = await User.findAll({ where: { username: recipients } });
      const messages = recipientUsers.map((recipientUser) => {
        return { senderId: senderUser.id, message, groupId: recipientUser.id };
      });
      await Message.bulkCreate(messages);
      res.json({ message: 'Message sent successfully' });
    }
  } catch (err) {
    console.error('Error occurred while sending message:', err);
    res.status(500).json({ message: 'Error occurred while sending message' });
  }
});

// Create group endpoint
app.post('/group/create', authenticateUser, async (req, res) => {
  const { name } = req.body;
  const { username } = req.user;

  try {
    const owner = await User.findOne({ where: { username } });
    const group = await Group.create({ name, ownerId: owner.id });
    await owner.addGroup(group);
    res.json({ message: 'Group created successfully' });
  } catch (err) {
    console.error('Error occurred while creating group:', err);
    res.status(500).json({ message: 'Error occurred while creating group' });
  }
});

// Join group through link endpoint
app.post('/group/join/:groupId', authenticateUser, async (req, res) => {
  const { groupId } = req.params;
  const { username } = req.user;

  try {
    const group = await Group.findByPk(groupId);
    if (!group) {
      res.status(404).json({ message: 'Group not found' });
    } else {
      const user = await User.findOne({ where: { username } });
      if (user.groups.includes(group.id)) {
        res.status(409).json({ message: 'You are already a member of this group' });
      } else {
        await user.addGroup(group);
        res.json({ message: 'Joined the group successfully' });
      }
    }
  } catch (err) {
    console.error('Error occurred while joining the group:', err);
    res.status(500).json({ message: 'Error occurred while joining the group' });
  }
});

// Add users to group endpoint
app.post('/group/add-users', authenticateUser, async (req, res) => {
  const { groupId, users } = req.body;

  try {
    const group = await Group.findByPk(groupId);
    if (!group) {
      res.status(404).json({ message: 'Group not found' });
    } else {
      const userList = await User.findAll({ where: { username: users } });
      await group.addUsers(userList);
      res.json({ message: 'Users added to group successfully' });
    }
  } catch (err) {
    console.error('Error occurred while adding users to group:', err);
    res.status(500).json({ message: 'Error occurred while adding users to group' });
  }
});

// Group chat endpoint
app.post('/chat/group', authenticateUser, async (req, res) => {
  const { groupId, message } = req.body;
  const sender = req.user.username;

  try {
    const senderUser = await User.findOne({ where: { username: sender } });
    const group = await Group.findByPk(groupId);
    if (!senderUser || !group) {
      res.status(404).json({ message: 'Sender or group not found' });
    } else {
      const msg = await Message.create({ senderId: senderUser.id, message, groupId });
      res.json({ message: 'Group message sent successfully' });
    }
  } catch (err) {
    console.error('Error occurred while sending group message:', err);
    res.status(500).json({ message: 'Error occurred while sending group message' });
  }
});

// Get group chat messages with pagination
app.get('/chat/group/:groupId', authenticateUser, async (req, res) => {
  const { groupId } = req.params;
  const { page = 1, limit = 10 } = req.query; // Default page: 1, limit: 10

  const offset = (page - 1) * limit;

  try {
    const group = await Group.findByPk(groupId);
    if (!group) {
      res.status(404).json({ message: 'Group not found' });
    } else {
      const messages = await Message.findAll({
        where: { groupId },
        include: [{ model: User, as: 'sender' }],
        order: [['createdAt', 'DESC']],
        limit,
        offset,
      });
      res.json(messages);
    }
  } catch (err) {
    console.error('Error occurred while retrieving group messages:', err);
    res.status(500).json({ message: 'Error occurred while retrieving group messages' });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});


// This code provides the following endpoints:

// POST /register - Allows users to register by providing a username and password.
// POST /login - Allows users to login by providing a username and password. Returns a JWT token upon successful authentication.
// POST /chat/one-to-one - Sends a one-to-one chat message. Requires authentication and expects a JSON payload with recipient and message fields.
// POST /chat/one-to-many - Sends a one-to-many chat message. Requires authentication and expects a JSON payload with recipients (comma-separated usernames) and message fields.
// POST /upload - Uploads a file (image or video) and sends it to the specified recipients. Requires authentication and expects a file field in the form data, along with a recipients field (comma-separated usernames).
// The /chat/group endpoint allows users to send group chat messages. It expects a groupId and message in the request body. The endpoint creates a new Message document with the sender, group ID, and message content.

// The /group/create endpoint is modified to assign the owner of the group. When creating a new group, the owner field is set to the _id of the user who created the group.

// The /chat/group/:groupId endpoint retrieves the group chat messages for a given group ID. It uses populate to populate the sender field with the username of the sender for each message.

// newman run http://localhost:3000 -e my_environment.json --export-collection my_api_collection.json


// newman run <Your_API_Endpoint_URL> -e <Your_Environment_File.json> -u <username>:<password> --export-collection <Output_File_Name.json>
