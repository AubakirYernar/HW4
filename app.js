require('dotenv').config();
const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const app = express();

// Подключение к MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// Модель пользователя
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  images: [String],
  emailToken: String,
  isVerified: { type: Boolean, default: false }
});
const User = mongoose.model('User', UserSchema);

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
const upload = multer();

// Маршруты
app.get('/', (req, res) => res.render('index'));

// Логин
app.get('/login', (req, res) => res.render('login'));
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (user && await bcrypt.compare(password, user.password)) {
    req.session.user = user;
    res.redirect('/user');
  } else {
    res.send('Invalid credentials');
  }
});

// Регистрация
app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
      username: req.body.username,
      email: req.body.email,
      password: hashedPassword,
      emailToken: require('crypto').randomBytes(64).toString('hex')
    });
    await user.save();
    res.redirect('/login');
  } catch (err) {
    res.send('Error registering user');
  }
});

// Пользователь
app.get('/user', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('user', { user: req.session.user });
});

app.post('/user/change-password', async (req, res) => {
  const user = await User.findById(req.session.user._id);
  if (await bcrypt.compare(req.body.oldPassword, user.password)) {
    user.password = await bcrypt.hash(req.body.newPassword, 10);
    await user.save();
    res.redirect('/user');
  } else {
    res.send('Old password incorrect');
  }
});

app.post('/user/upload', upload.single('image'), async (req, res) => {
  const user = await User.findById(req.session.user._id);
  user.images.push(req.file.buffer.toString('base64'));
  await user.save();
  res.redirect('/user');
});

// Админ
app.get('/admin', (req, res) => {
  if (!req.session.admin) return res.render('admin', { auth: false });
  User.find({}).then(users => res.render('admin', { auth: true, users }));
});

app.post('/admin', async (req, res) => {
  if (req.body.password === 'qwerty123') {
    req.session.admin = true;
    res.redirect('/admin');
  } else {
    res.send('Wrong admin password');
  }
});

// CRUD операции
app.post('/admin/create', async (req, res) => {
  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  const user = new User({
    username: req.body.username,
    email: req.body.email,
    password: hashedPassword
  });
  await user.save();
  res.redirect('/admin');
});

app.post('/admin/update/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  user.username = req.body.username || user.username;
  user.email = req.body.email || user.email;
  if (req.body.password) user.password = await bcrypt.hash(req.body.password, 10);
  await user.save();
  res.redirect('/admin');
});

app.post('/admin/delete/:id', async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.redirect('/admin');
});

// Выход
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));