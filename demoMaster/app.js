const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const moment = require('moment');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
app.set('view engine', 'ejs');
// 设置视图文件目录（通常是views）
app.set('views', './views');
const PORT = 3000;
const saltRounds = 10; // 密码加密强度

// 确保上传目录存在
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// 配置文件上传
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        // 生成唯一的文件名，避免冲突
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
        const ext = path.extname(file.originalname);
        cb(null, file.fieldname + '-' + uniqueSuffix + ext);
    }
});

// 文件过滤
const fileFilter = (req, file, cb) => {
    // 允许的文件类型
    const allowedTypes = [
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/pdf',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'image/jpeg',
        'image/png'
    ];
    
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('不支持的文件类型'), false);
    }
};

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 限制文件大小为10MB
    fileFilter: fileFilter
});

// 配置模板引擎
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// 中间件
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json()); // 解析JSON请求体
app.use('/uploads', express.static(uploadDir));

// 配置会话
app.use(session({
    secret: 'equipment-booking-secret-key', // 生产环境需更换为随机字符串
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // 生产环境使用HTTPS时设为true
}));

// 登录验证中间件
function requireLogin(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    } else {
        res.redirect('/login?redirect=' + encodeURIComponent(req.originalUrl));
    }
}

// 连接SQLite数据库
const db = new sqlite3.Database('equipment_booking.db', (err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Connected to the equipment booking database.');
    
    // 初始化数据库表
    initDB();
});

// 初始化数据库表结构
function initDB() {
    // 创建设备表
    db.run(`CREATE TABLE IF NOT EXISTS equipment (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        description TEXT,
        status TEXT NOT NULL DEFAULT '可用', -- 新增状态字段，默认为"可用"
        location TEXT, -- 新增地点字段
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
        if (err) {
            console.error('Error creating equipment table:', err.message);
        } else {
            // 检查是否有设备，如果没有则添加测试设备
            db.get("SELECT COUNT(*) as count FROM equipment", (err, row) => {
                if (err) {
                    console.error('Error checking equipment count:', err.message);
                    return;
                }
                
                if (!row || row.count === 0) {
                    const testEquipment = [
                        ['投影仪A', '投影设备', '会议室主投影仪', '可用'],
                        ['笔记本电脑B', '计算机', '高性能开发笔记本', '可用'],
                        ['摄像机C', '摄像设备', '高清会议摄像机', '维修中'],
                        ['麦克风D', '音频设备', '无线麦克风套装', '可用']
                    ];
                    
                    const stmt = db.prepare(`INSERT INTO equipment (name, type, description, status) 
                                           VALUES (?, ?, ?, ?)`);
                    testEquipment.forEach(equip => {
                        stmt.run(equip[0], equip[1], equip[2], equip[3]);
                    });
                    stmt.finalize();
                    console.log('Added test equipment.');
                } else {
                    // 如果表已存在，添加status字段（如果不存在）
                    db.run(`ALTER TABLE equipment ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT '可用'`, (err) => {
                        if (err) {
                            console.log('Status column already exists or error adding it:', err.message);
                        } else {
                            console.log('Added status column to equipment table');
                        }
                    });
                }
            });
        }
    });


    // 创建预约表
    db.run(`CREATE TABLE IF NOT EXISTS bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        equipment_id INTEGER NOT NULL,
        user_name TEXT NOT NULL,
        purpose TEXT,
        start_time TIMESTAMP NOT NULL,
        end_time TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (equipment_id) REFERENCES equipment(id)
    )`, (err) => {
        if (err) {
            console.error('Error creating bookings table:', err.message);
        }
    });

    // 创建附件表
    db.run(`CREATE TABLE IF NOT EXISTS attachments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        booking_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        originalname TEXT NOT NULL,
        mimetype TEXT NOT NULL,
        filesize INTEGER NOT NULL,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (booking_id) REFERENCES bookings(id) ON DELETE CASCADE
    )`, (err) => {
        if (err) {
            console.error('Error creating attachments table:', err.message);
        }
    });

    // 创建用户表
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        email TEXT UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
        if (err) {
            console.error('Error creating users table:', err.message);
        } else {
            console.log('Users table initialized or already exists');
        }
    });

    // 对于已存在的表，添加location字段
    db.run(`ALTER TABLE equipment ADD COLUMN IF NOT EXISTS location TEXT`, (err) => {
        if (err) {
            console.log('地点字段已存在或添加失败:', err.message);
        } else {
            console.log('成功添加地点字段到设备表');
        }
    });
}

// 登录注册相关路由
// 路由 - 显示登录页面
app.get('/login', (req, res) => {
    // 将查询参数 registered 传递给模板
    res.render('login', {
      error: null,
      registered: req.query.registered // 传递注册状态参数
    });
  });

app.get('/register', (req, res) => {
    res.render('register', { error: null });
});

// 路由 - 处理注册请求
app.post('/register', (req, res) => {
    const { username, password, email } = req.body;
  
    // 简单验证
    if (!username || !password) {
      return res.render('register', { error: '用户名和密码不能为空' });
    }
  
    // 邮箱格式验证（可选）
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (email && !emailRegex.test(email)) {
      return res.render('register', { error: '邮箱格式不正确' });
    }
  
    // 检查用户名是否已存在
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
      if (err) {
        return res.status(500).send(err.message);
      }
  
      if (user) {
        return res.render('register', { error: '用户名已存在' });
      }
  
      // 密码加密
      bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
        if (err) {
          return res.status(500).send(err.message);
        }
  
        // 创建新用户（需确保已创建 users 表）
        db.run(`INSERT INTO users (username, password, email) 
               VALUES (?, ?, ?)`, [username, hashedPassword, email], function(err) {
          if (err) {
            return res.render('register', { error: '注册失败，请稍后再试' });
          }
          // 注册成功后跳转到登录页，并提示注册成功
          res.redirect('/login?registered=true');
        });
      });
    });
  });

// 路由 - 处理登录请求
app.post('/login', (req, res) => {
    const { username, password } = req.body;
  
    // 简单验证
    if (!username || !password) {
      return res.render('login', {
        error: '用户名和密码不能为空',
        registered: null  // 登录失败时不需要显示注册成功提示
      });
    }
  
    // 查询数据库验证用户
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
      if (err) {
        return res.status(500).send(err.message);
      }
  
      if (!user) {
        return res.render('login', {
          error: '用户名不存在',
          registered: null
        });
      }
  
      // 使用bcrypt验证密码
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) {
          return res.status(500).send(err.message);
        }
  
        if (!isMatch) {
          return res.render('login', {
            error: '密码错误',
            registered: null
          });
        }
  
        // 登录成功 - 设置会话信息
        req.session.userId = user.id;
        req.session.username = user.username;
        
        // 检查是否有重定向参数
        const redirectUrl = req.query.redirect || '/';
        res.redirect(redirectUrl);
      });
    });
  });


app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        res.redirect('/login');
    });
});

// 主功能路由（需登录）
app.get('/', requireLogin, (req, res) => {
    // 获取视图类型，默认为日视图
    const viewType = req.query.view || 'day';
    // 获取基准日期，默认为今天
    const baseDate = req.query.date ? new Date(req.query.date) : new Date();
    const formattedBaseDate = moment(baseDate).format('YYYY-MM-DD');
    
    // 根据视图类型计算日期范围
    let startDate, endDate, displayDate, prevDate, nextDate;
    
    if (viewType === 'day') {
        startDate = moment(baseDate).startOf('day');
        endDate = moment(baseDate).endOf('day');
        displayDate = moment(baseDate).format('YYYY年MM月DD日');
        prevDate = moment(baseDate).subtract(1, 'day').format('YYYY-MM-DD');
        nextDate = moment(baseDate).add(1, 'day').format('YYYY-MM-DD');
    } else if (viewType === 'week') {
        // 周视图：从周日开始到周六结束
        startDate = moment(baseDate).startOf('week'); // 周日
        endDate = moment(baseDate).endOf('week');     // 周六
        displayDate = `${startDate.format('MM月DD日')} - ${endDate.format('MM月DD日')}`;
        prevDate = moment(baseDate).subtract(1, 'week').format('YYYY-MM-DD');
        nextDate = moment(baseDate).add(1, 'week').format('YYYY-MM-DD');
    } else if (viewType === 'month') {
        startDate = moment(baseDate).startOf('month');
        endDate = moment(baseDate).endOf('month');
        displayDate = moment(baseDate).format('YYYY年MM月');
        prevDate = moment(baseDate).subtract(1, 'month').format('YYYY-MM-DD');
        nextDate = moment(baseDate).add(1, 'month').format('YYYY-MM-DD');
    }
    
    // 获取所有设备
    db.all("SELECT * FROM equipment", (err, equipment) => {
        if (err) {
            return res.status(500).send(err.message);
        }
        
        // 获取日期范围内的所有预约
        db.all(`SELECT * FROM bookings 
                WHERE start_time <= ? AND end_time >= ?`, 
                [endDate.toISOString(), startDate.toISOString()], (err, bookings) => {
            if (err) {
                return res.status(500).send(err.message);
            }
            
            // 向模板传递所有必要的变量
            res.render('calendar', {
                viewType: viewType,
                date: formattedBaseDate,
                baseDate: formattedBaseDate,
                startDate: startDate,
                endDate: endDate,
                displayDate: displayDate,
                prevDate: prevDate,
                nextDate: nextDate,
                equipment: equipment,
                bookings: bookings,
                moment: moment,
                user: req.session // 传递用户信息到模板
            });
        });
    });
});

app.get('/bookings/new', requireLogin, (req, res) => {
    const viewType = req.query.view || 'day';
    const baseDate = req.query.date ? req.query.date : moment().format('YYYY-MM-DD');
    
    // 计算默认的开始和结束时间
    const defaultStartTime = moment(baseDate).hour(9).format('YYYY-MM-DDTHH:mm');
    const defaultEndTime = moment(baseDate).hour(10).format('YYYY-MM-DDTHH:mm');
    
    // 获取所有设备
    db.all("SELECT * FROM equipment", (err, equipment) => {
        if (err) {
            return res.status(500).send(err.message);
        }
        
        res.render('booking-form', {
            viewType: viewType,
            baseDate: baseDate,
            equipment: equipment,
            defaultStartTime: defaultStartTime,
            defaultEndTime: defaultEndTime,
            error: null,
            moment: moment,
            user: req.session // 传递用户信息到模板
        });
    });
});

app.get('/equipment', requireLogin, (req, res) => {
    db.all("SELECT * FROM equipment ORDER BY created_at DESC", (err, equipment) => {
        if (err) {
            return res.status(500).send(err.message);
        }
        res.render('equipment', { 
            equipment: equipment,
            user: req.session // 传递用户信息到模板
        });
    });
});

app.post('/equipment/add', requireLogin, (req, res) => {
    const { name, type, description, status, location } = req.body;
    
    db.run(`INSERT INTO equipment (name, type, description, status, location) 
           VALUES (?, ?, ?, ?, ?)`, 
           [name, type, description, status || '可用', location], 
           function(err) {
        if (err) {
            return res.status(500).send(err.message);
        }
        res.redirect('/equipment');
    });
});



// 设备删除功能
app.post('/equipment/delete/:id', (req, res) => {
    const equipmentId = req.params.id;
    
    db.run('DELETE FROM equipment WHERE id = ?', [equipmentId], function(err) {
      if (err) {
        return console.error(err.message);
      }
      res.redirect('/equipment'); // 删除后重定向到设备列表
    });
  });
  
  
 // 更新设备编辑路由，添加登录验证并传递用户信息
app.get('/equipment/edit/:id', requireLogin, (req, res) => {
    const equipmentId = req.params.id;
    
    db.get('SELECT * FROM equipment WHERE id = ?', [equipmentId], (err, row) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('数据库错误: ' + err.message);
        }
        if (!row) {
            return res.status(404).send('设备不存在');
        }
        res.render('edit-equipment', { 
            equipment: row,
            user: req.session 
        });
    });
});
  

// 处理设备更新
app.post('/equipment/update/:id', requireLogin, (req, res) => {
    const equipmentId = req.params.id;
    // 从请求体中获取location参数
    const { name, type, description, status, location } = req.body;
    
    const sql = `UPDATE equipment 
                 SET name = ?, type = ?, description = ?, status = ?, location = ?
                 WHERE id = ?`;
                 
    // 确保使用从请求体中获取的location变量
    db.run(sql, [name, type, description, status, location, equipmentId], function(err) {
        if (err) {
            console.error(err.message);
            return res.status(500).send('更新失败: ' + err.message);
        }
        res.redirect('/equipment'); // 更新后重定向到设备列表
    });
});








app.post('/bookings/add', requireLogin, upload.array('attachments', 5), (req, res) => {
    const { equipment_id, purpose, start_time, end_time, view, date } = req.body;
    const viewType = view || 'day';
    const files = req.files || [];
    const userName = req.session.username; // 使用当前登录用户名
    
    // 检查时间冲突
    db.get(`SELECT * FROM bookings 
            WHERE equipment_id = ? 
            AND (
                (start_time < ? AND end_time > ?) OR
                (start_time < ? AND end_time > ?) OR
                (start_time >= ? AND end_time <= ?)
            )`, [equipment_id, end_time, start_time, end_time, start_time, start_time, end_time], 
            (err, conflictingBooking) => {
        if (err) {
            // 如果是文件上传错误
            if (err.message === '不支持的文件类型') {
                db.all("SELECT * FROM equipment", (eqErr, equipment) => {
                    return res.render('booking-form', {
                        viewType: viewType,
                        baseDate: date,
                        equipment: equipment,
                        defaultStartTime: start_time || moment(date).hour(9).format('YYYY-MM-DDTHH:mm'),
                        defaultEndTime: end_time || moment(date).hour(10).format('YYYY-MM-DDTHH:mm'),
                        error: '不支持的文件类型，请上传Word、Excel、PowerPoint、PDF或图片文件',
                        moment: moment,
                        user: req.session
                    });
                });
            }
            return res.status(500).send(err.message);
        }
        
        if (conflictingBooking) {
            db.all("SELECT * FROM equipment", (eqErr, equipment) => {
                return res.render('booking-form', {
                    viewType: viewType,
                    baseDate: date,
                    equipment: equipment,
                    defaultStartTime: start_time,
                    defaultEndTime: end_time,
                    error: '预约时间冲突，请选择其他时间',
                    moment: moment,
                    user: req.session
                });
            });
            return;
        }
        
        // 创建新预约（使用当前登录用户作为预约人）
        db.run(`INSERT INTO bookings (equipment_id, user_name, purpose, start_time, end_time) 
               VALUES (?, ?, ?, ?, ?)`, 
               [equipment_id, userName, purpose, start_time, end_time], function(err) {
            if (err) {
                return res.status(500).send(err.message);
            }
            
            const bookingId = this.lastID;
            
            // 如果有附件，保存附件信息到数据库
            if (files.length > 0) {
                const stmt = db.prepare(`INSERT INTO attachments 
                                       (booking_id, filename, originalname, mimetype, filesize) 
                                       VALUES (?, ?, ?, ?, ?)`);
                
                files.forEach(file => {
                    stmt.run(
                        bookingId,
                        file.filename,
                        file.originalname,
                        file.mimetype,
                        file.size
                    );
                });
                
                stmt.finalize();
            }
            
            res.redirect(`/?view=${viewType}&date=${date}`);
        });
    });
});

app.get('/bookings/delete/:id', requireLogin, (req, res) => {
    const bookingId = req.params.id;
    const viewType = req.query.view || 'day';
    const date = req.query.date || moment().format('YYYY-MM-DD');
    
    // 先删除相关附件
    db.get("SELECT * FROM attachments WHERE booking_id = ?", [bookingId], (err, attachments) => {
        if (err) {
            return res.status(500).send(err.message);
        }
        
        // 删除文件系统中的附件
        if (attachments) {
            db.all("SELECT filename FROM attachments WHERE booking_id = ?", [bookingId], (err, files) => {
                if (err) {
                    console.error('Error getting attachments:', err.message);
                } else {
                    files.forEach(file => {
                        const filePath = path.join(uploadDir, file.filename);
                        if (fs.existsSync(filePath)) {
                            fs.unlink(filePath, (err) => {
                                if (err) {
                                    console.error('Error deleting file:', err.message);
                                }
                            });
                        }
                    });
                }
                
                // 从数据库删除附件记录
                db.run("DELETE FROM attachments WHERE booking_id = ?", [bookingId], (err) => {
                    if (err) {
                        console.error('Error deleting attachments from DB:', err.message);
                    }
                });
            });
        }
        
        // 删除预约
        db.run("DELETE FROM bookings WHERE id = ?", [bookingId], function(err) {
            if (err) {
                return res.status(500).send(err.message);
            }
            res.redirect(`/?view=${viewType}&date=${date}`);
        });
    });
});

// 预约详情接口
app.get('/bookings/details/:id', requireLogin, (req, res) => {
    try {
        const bookingId = parseInt(req.params.id, 10);
        
        // 验证ID格式
        if (isNaN(bookingId)) {
            return res.status(400).json({
                success: false,
                message: '无效的预约ID，必须为数字'
            });
        }
        
        // 查询预约基本信息
        db.get("SELECT * FROM bookings WHERE id = ?", [bookingId], (err, booking) => {
            if (err) {
                console.error('查询预约信息失败:', err);
                return res.status(500).json({
                    success: false,
                    message: '服务器错误，查询预约信息失败'
                });
            }
            
            if (!booking) {
                return res.status(404).json({
                    success: false,
                    message: `未找到ID为${bookingId}的预约记录`
                });
            }
            
            // 查询关联的设备信息
            db.get("SELECT * FROM equipment WHERE id = ?", [booking.equipment_id], (err, equipment) => {
                if (err) {
                    console.error('查询设备信息失败:', err);
                    return res.status(500).json({
                        success: false,
                        message: '服务器错误，查询设备信息失败'
                    });
                }
                
                // 查询关联的附件信息
                db.all("SELECT * FROM attachments WHERE booking_id = ?", [bookingId], (err, attachments) => {
                    if (err) {
                        console.error('查询附件信息失败:', err);
                        return res.status(500).json({
                            success: false,
                            message: '服务器错误，查询附件信息失败'
                        });
                    }
                    
                    // 格式化时间显示
                    const formattedBooking = {
                        ...booking,
                        start_time_formatted: moment(booking.start_time).format('YYYY-MM-DD HH:mm'),
                        end_time_formatted: moment(booking.end_time).format('YYYY-MM-DD HH:mm'),
                        created_at_formatted: moment(booking.created_at).format('YYYY-MM-DD HH:mm')
                    };
                    
                    // 构建响应数据
                    res.status(200).json({
                        success: true,
                        data: {
                            booking: formattedBooking,
                            equipment: equipment || null,
                            attachments: attachments.map(att => ({
                                ...att,
                                url: `/uploads/${att.filename}`, // 附件访问URL
                                uploaded_at_formatted: moment(att.uploaded_at).format('YYYY-MM-DD HH:mm')
                            }))
                        }
                    });
                });
            });
        });
    } catch (error) {
        console.error('获取预约详情异常:', error);
        res.status(500).json({
            success: false,
            message: '服务器内部错误，获取预约详情失败'
        });
    }
});




// 添加中国城市地图页面路由
app.get('/china-map', requireLogin, (req, res) => {
    db.all("SELECT * FROM equipment", (err, equipment) => {
        if (err) {
            return res.status(500).send(err.message);
        }
        res.render('china-map', { 
            user: req.session,
            equipment: equipment // 将设备数据传递到地图页面
        });
    });
});



// 启动服务器
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
