
const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = 3000;

// Configure body-parser and multer for handling form data
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
const upload = multer({ dest: 'uploads/' });

// Secret key for JWT
const secretKey = 'your-secret-key';

// Connect to SQLite database
const db = new sqlite3.Database('chatapp.db');

// Create user table
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,
    profilePicture TEXT DEFAULT 'default.jpg'
  )
`);

// Create group table
db.run(`
  CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    owner_id INTEGER,
    FOREIGN KEY (owner_id) REFERENCES users (id)
  )
`);

// Create message table
db.run(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER,
    group_id INTEGER,
    message TEXT,
    file TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users (id),
    FOREIGN KEY (group_id) REFERENCES groups (id)
  )
`);

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
app.post('/register', upload.single('profilePicture'), (req, res) => {
  const { username, password } = req.body;
  const profilePicture = req.file ? req.file.filename : 'default.jpg'; // Use default image if no profile picture is uploaded

  const query = `
    INSERT INTO users (username, password, profilePicture)
    VALUES (?, ?, ?)
  `;
  const values = [username, password, profilePicture];

  db.run(query, values, (err) => {
    if (err) {
      res.status(500).json({ message: 'Error occurred while registering user' });
    } else {
      res.json({ message: 'User registered successfully' });
    }
  });
});

// Get all users endpoint
app.get('/users', (req, res) => {
  const query = `
    SELECT * FROM users
  `;

  db.all(query, (err, rows) => {
    if (err) {
      res.status(500).json({ message: 'Error occurred while retrieving users' });
    } else {
      res.json(rows);
    }
  });
});

// Update user information endpoint
app.put('/user', authenticateUser, upload.single('profilePicture'), (req, res) => {
  const { username } = req.user;
  const profilePicture = req.file ? req.file.filename : req.user.profilePicture; // Use existing profile picture if no new picture is uploaded

  const query = `
    UPDATE users
    SET profilePicture = ?
    WHERE username = ?
  `;
  const values = [profilePicture, username];

  db.run(query, values, (err) => {
    if (err) {
      res.status(500).json({ message: 'Error occurred while updating user information' });
    } else {
      res.json({ message: 'User information updated successfully' });
    }
  });
});

// User login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const query = `
    SELECT * FROM users
    WHERE username = ? AND password = ?
  `;
  const values = [username, password];

  db.get(query, values, (err, row) => {
    if (err) {
      res.status(500).json({ message: 'Error occurred while logging in' });
    } else if (!row) {
      res.status(401).json({ message: 'Invalid username or password' });
    } else {
      const token = jwt.sign({ username }, secretKey);
      res.json({ token });
    }
  });
});

// One-to-one chat endpoint
app.post('/chat/one-to-one', authenticateUser, (req, res) => {
  const { recipient, message } = req.body;
  const sender = req.user.username;

  const query = `
    INSERT INTO messages (sender_id, message)
    VALUES ((SELECT id FROM users WHERE username = ?), ?)
  `;
  const values = [sender, message];

  db.run(query, values, (err) => {
    if (err) {
      res.status(500).json({ message: 'Error occurred while sending message' });
    } else {
      res.json({ message: 'Message sent successfully' });
    }
  });
});

// One-to-many chat endpoint
app.post('/chat/one-to-many', authenticateUser, (req, res) => {
  const { recipients, message } = req.body;
  const sender = req.user.username;

  const query = `
    INSERT INTO messages (sender_id, message)
    VALUES ((SELECT id FROM users WHERE username = ?), ?)
  `;
  const values = [sender, message];

  db.serialize(() => {
    db.run('BEGIN TRANSACTION');
    recipients.forEach((recipient) => {
      db.run(query, values, (err) => {
        if (err) {
          console.error(err);
        }
      });
    });
    db.run('COMMIT', (err) => {
      if (err) {
        res.status(500).json({ message: 'Error occurred while sending message' });
      } else {
        res.json({ message: 'Message sent successfully' });
      }
    });
  });
});

// Create group endpoint
app.post('/group/create', authenticateUser, (req, res) => {
  const { name } = req.body;
  const { username } = req.user;

  const query = `
    INSERT INTO groups (name, owner_id)
    VALUES (?, (SELECT id FROM users WHERE username = ?))
  `;
  const values = [name, username];

  db.run(query, values, function (err) {
    if (err) {
      res.status(500).json({ message: 'Error occurred while creating group' });
    } else {
      const groupId = this.lastID;
      const updateQuery = `
        UPDATE users
        SET groups = GROUP_CONCAT(groups, ?)
        WHERE username = ?
      `;
      const updateValues = [',' + groupId, username];

      db.run(updateQuery, updateValues, (err) => {
        if (err) {
          res.status(500).json({ message: 'Error occurred while creating group' });
        } else {
          res.json({ message: 'Group created successfully' });
        }
      });
    }
  });
});

// Join group through link endpoint
app.post('/group/join/:groupId', authenticateUser, (req, res) => {
  const { groupId } = req.params;
  const { username } = req.user;

  const query = `
    SELECT * FROM groups
    WHERE id = ?
  `;
  const values = [groupId];

  db.get(query, values, (err, row) => {
    if (err) {
      res.status(500).json({ message: 'Error occurred while joining the group' });
    } else if (!row) {
      res.status(404).json({ message: 'Group not found' });
    } else if (row.users.includes(username)) {
      res.status(409).json({ message: 'You are already a member of this group' });
    } else {
      const updateQuery = `
        UPDATE groups
        SET users = GROUP_CONCAT(users, ?)
        WHERE id = ?
      `;
      const updateValues = [',' + username, groupId];

      db.run(updateQuery, updateValues, (err) => {
        if (err) {
          res.status(500).json({ message: 'Error occurred while joining the group' });
        } else {
          const userUpdateQuery = `
            UPDATE users
            SET groups = GROUP_CONCAT(groups, ?)
            WHERE username = ?
          `;
          const userUpdateValues = [',' + groupId, username];

          db.run(userUpdateQuery, userUpdateValues, (err) => {
            if (err) {
              res.status(500).json({ message: 'Error occurred while joining the group' });
            } else {
              res.json({ message: 'Joined the group successfully' });
            }
          });
        }
      });
    }
  });
});

// Add users to group endpoint
app.post('/group/add-users', authenticateUser, (req, res) => {
  const { groupId, users } = req.body;

  const query = `
    UPDATE groups
    SET users = GROUP_CONCAT(users, ?)
    WHERE id = ?
  `;
  const values = [',' + users.join(','), groupId];

  db.run(query, values, (err) => {
    if (err) {
      res.status(500).json({ message: 'Error occurred while adding users to group' });
    } else {
      res.json({ message: 'Users added to group successfully' });
    }
  });
});

// Group chat endpoint
app.post('/chat/group', authenticateUser, (req, res) => {
  const { groupId, message } = req.body;
  const sender = req.user.username;

  const query = `
    INSERT INTO messages (sender_id, group_id, message)
    VALUES ((SELECT id FROM users WHERE username = ?), ?, ?)
  `;
  const values = [sender, groupId, message];

  db.run(query, values, (err) => {
    if (err) {
      res.status(500).json({ message: 'Error occurred while sending group message' });
    } else {
      res.json({ message: 'Group message sent successfully' });
    }
  });
});

// Get group chat messages with pagination
app.get('/chat/group/:groupId', authenticateUser, (req, res) => {
  const { groupId } = req.params;
  const { page = 1, limit = 10 } = req.query; // Default page: 1, limit: 10

  const offset = (page - 1) * limit;

  const query = `
    SELECT messages.*, users.username AS sender
    FROM messages
    JOIN users ON messages.sender_id = users.id
    WHERE group_id = ?
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `;
  const values = [groupId, limit, offset];

  db.all(query, values, (err, rows) => {
    if (err) {
      res.status(500).json({ message: 'Error occurred while retrieving group messages' });
    } else {
      res.json(rows);
    }
  });
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
