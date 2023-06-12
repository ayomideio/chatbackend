const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const mongoosePaginate = require('mongoose-paginate-v2');

const app = express();
const port = 3000;

// Configure body-parser and multer for handling form data
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
const upload = multer({ dest: 'uploads/' });

// Secret key for JWT
const secretKey = 'your-secret-key';

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/chatapp', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User schema
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    groups: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Group' }],
    profilePicture: { type: String, default: 'default.jpg' }, // Default profile picture
  });
  
  
const User = mongoose.model('User', userSchema);

//Group Schema
const groupSchema = new mongoose.Schema({
    name: String,
    users: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  });
  
  const Group = mongoose.model('Group', groupSchema);
  
// Message schema
const messageSchema = new mongoose.Schema({
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    group: { type: mongoose.Schema.Types.ObjectId, ref: 'Group' },
    message: String,
    file: String,
    createdAt: { type: Date, default: Date.now },
  });
  
  messageSchema.plugin(mongoosePaginate);

const Message = mongoose.model('Message', messageSchema);

// Middleware for user authentication
function authenticateUser(req, res, next) {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, secretKey);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}


  // Get all users endpoint
  app.get('/', (req, res) => {
  
      res.json("Chat API IS LIVE");
   
  });

// User registration endpoint
app.post('/register', upload.single('profilePicture'), async (req, res) => {
    const { username, password } = req.body;
    const profilePicture = req.file ? req.file.filename : 'default.jpg'; // Use default image if no profile picture is uploaded
  
    try {
      const newUser = new User({ username, password, profilePicture });
      await newUser.save();
      res.json({ message: 'User registered successfully' });
    } catch (err) {
      res.status(500).json({ message: 'Error occurred while registering user' });
    }
  });
  
  
  // Get all users endpoint
  app.get('/users', async (req, res) => {
    try {
      const users = await User.find({});
      res.json(users);
    } catch (err) {
      res.status(500).json({ message: 'Error occurred while retrieving users' });
    }
  });
  
  
  // Update user information endpoint
  app.put('/user', authenticateUser, upload.single('profilePicture'), async (req, res) => {
    const { username } = req.user;
    const profilePicture = req.file ? req.file.filename : req.user.profilePicture; // Use existing profile picture if no new picture is uploaded
  
    try {
      const updatedUser = await User.findOneAndUpdate(
        { username },
        { profilePicture },
        { new: true }
      );
      res.json(updatedUser);
    } catch (err) {
      res.status(500).json({ message: 'Error occurred while updating user information' });
    }
  });
  
  
  // User login endpoint
  app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    // You may want to add more validation and checks here
  
    try {
      const user = await User.findOne({ username, password });
      if (!user) {
        return res.status(401).json({ message: 'Invalid username or password' });
      }
  
      const token = jwt.sign({ username }, secretKey);
      res.json({ token });
    } catch (err) {
      res.status(500).json({ message: 'Error occurred while logging in' });
    }
  });
  
  
  // One-to-one chat endpoint
  app.post('/chat/one-to-one', authenticateUser, async (req, res) => {
    const { recipient, message } = req.body;
  
    const sender = req.user.username;
    const newMessage = new Message({ sender, recipient, message });
    try {
      await newMessage.save();
      res.json({ message: 'Message sent successfully' });
    } catch (err) {
      res.status(500).json({ message: 'Error occurred while sending message' });
    }
  });
  
  
  // One-to-many chat endpoint
  app.post('/chat/one-to-many', authenticateUser, async (req, res) => {
    const { recipients, message } = req.body;
  
    const sender = req.user.username;
    recipients.forEach(async (recipient) => {
      const newMessage = new Message({ sender, recipient, message });
      try {
        await newMessage.save();
      } catch (err) {
        console.error(err);
      }
    });
  
    res.json({ message: 'Message sent successfully' });
  });
  
  
  // Create group endpoint
  app.post('/group/create', authenticateUser, async (req, res) => {
    const { name } = req.body;
    const { username } = req.user;
  
    const group = new Group({ name, users: [username], owner: req.user._id });
    try {
      const savedGroup = await group.save();
      await User.findOneAndUpdate(
        { username },
        { $push: { groups: savedGroup._id } }
      );
      res.json({ message: 'Group created successfully' });
    } catch (err) {
      res.status(500).json({ message: 'Error occurred while creating group' });
    }
  });
  
  
  // Join group through link endpoint
  app.post('/group/join/:groupId', authenticateUser, async (req, res) => {
    const { groupId } = req.params;
    const { username } = req.user;
  
    try {
      const group = await Group.findById(groupId);
      if (!group) {
        return res.status(404).json({ message: 'Group not found' });
      }
  
      if (group.users.includes(username)) {
        return res.status(409).json({ message: 'You are already a member of this group' });
      }
  
      group.users.push(username);
      const savedGroup = await group.save();
      await User.findOneAndUpdate(
        { username },
        { $push: { groups: savedGroup._id } }
      );
      res.json({ message: 'Joined the group successfully' });
    } catch (err) {
      res.status(500).json({ message: 'Error occurred while joining the group' });
    }
  });
  
  
  // Add users to group endpoint
  app.post('/group/add-users', authenticateUser, async (req, res) => {
    const { groupId, users } = req.body;
  
    try {
      const updatedGroup = await Group.findByIdAndUpdate(
        groupId,
        { $push: { users: { $each: users } } },
        { new: true }
      );
      res.json({ message: 'Users added to group successfully' });
    } catch (err) {
      res.status(500).json({ message: 'Error occurred while adding users to group' });
    }
  });
  
  
  // Group chat endpoint
  app.post('/chat/group', authenticateUser, async (req, res) => {
    const { groupId, message } = req.body;
  
    const sender = req.user.username;
    const newMessage = new Message({ sender, group: groupId, message });
    try {
      await newMessage.save();
      res.json({ message: 'Group message sent successfully' });
    } catch (err) {
      res.status(500).json({ message: 'Error occurred while sending group message' });
    }
  });
  
  
  // Get group chat messages with pagination
  app.get('/chat/group/:groupId', authenticateUser, async (req, res) => {
    const { groupId } = req.params;
    const { page = 1, limit = 10 } = req.query; // Default page: 1, limit: 10
  
    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      populate: { path: 'sender', select: 'username' },
      sort: { createdAt: -1 }, // Sort by creation timestamp in descending order
    };
  
    try {
      const result = await Message.paginate({ group: groupId }, options);
      res.json(result);
    } catch (err) {
      res.status(500).json({ message: 'Error occurred while retrieving group chat messages' });
    }
  });
  
  
  // File upload endpoint
  app.post('/upload', authenticateUser, upload.single('file'), async (req, res) => {
    const { filename } = req.file;
  
    const sender = req.user.username;
    const recipients = req.body.recipients.split(',');
  
    recipients.forEach(async (recipient) => {
      const newMessage = new Message({ sender, recipient, file: filename });
      try {
        await newMessage.save();
      } catch (err) {
        console.error(err);
      }
    });
  
    res.json({ message: 'File uploaded successfully' });
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
