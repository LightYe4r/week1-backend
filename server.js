require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const os = require('os');
const cors = require('cors');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const winston = require('winston');
const WinstonCloudWatch = require('winston-cloudwatch');

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret';

// CORS 설정
app.use(cors());
app.use(express.json());

// Winston Logger 설정
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    // 콘솔 출력
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// CloudWatch Logs 설정 (AWS 환경에서만 활성화)
if (process.env.AWS_REGION) {
  const cloudwatchConfig = {
    logGroupName: process.env.LOG_GROUP_NAME || '/aws/ec2/backend-server',
    logStreamName: `${os.hostname()}-${new Date().toISOString().split('T')[0]}`,
    awsRegion: process.env.AWS_REGION || 'ap-northeast-2',
    jsonMessage: true,
    retentionInDays: 7
  };

  logger.add(new WinstonCloudWatch(cloudwatchConfig));
  logger.info('CloudWatch Logs 연동 완료', cloudwatchConfig);
} else {
  logger.info('로컬 환경 - CloudWatch Logs 비활성화');
}

// Swagger 설정
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: '3-Tier Backend API',
      version: '1.0.0',
      description: '3-Tier 웹 애플리케이션 백엔드 API 문서 (Swagger + CloudWatch 연동)',
      contact: {
        name: 'API Support',
      },
    },
    servers: [
      {
        url: `http://localhost:${PORT}`,
        description: 'Development server',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'JWT 토큰을 입력하세요 (Bearer 제외)',
        },
      },
    },
    security: [{
      bearerAuth: [],
    }],
  },
  apis: ['./server.js'],
};

const swaggerDocs = swaggerJsdoc(swaggerOptions);

// MySQL/RDS 연결 풀
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

let pool;

// 서버 정보 가져오기
function getServerInfo() {
  const networkInterfaces = os.networkInterfaces();
  let ipAddress = 'unknown';
  
  for (const [name, interfaces] of Object.entries(networkInterfaces)) {
    for (const iface of interfaces) {
      if (iface.family === 'IPv4' && !iface.internal) {
        ipAddress = iface.address;
        break;
      }
    }
    if (ipAddress !== 'unknown') break;
  }

  const uptime = os.uptime();
  const days = Math.floor(uptime / 86400);
  const hours = Math.floor((uptime % 86400) / 3600);
  const minutes = Math.floor((uptime % 3600) / 60);

  return {
    hostname: os.hostname(),
    ip: ipAddress,
    instanceId: process.env.INSTANCE_ID || 'unknown',
    region: process.env.AWS_REGION || 'ap-northeast-2',
    uptime: `${days}일 ${hours}시간 ${minutes}분`,
    loadAvg: os.loadavg().map(load => load.toFixed(2)).join(', '),
    platform: os.platform(),
    cpus: os.cpus().length,
    totalMemory: (os.totalmem() / 1024 / 1024 / 1024).toFixed(2) + ' GB',
    freeMemory: (os.freemem() / 1024 / 1024 / 1024).toFixed(2) + ' GB'
  };
}

// DB 초기화 및 테이블 생성
async function initializeDatabase() {
  try {
    pool = mysql.createPool(dbConfig);
    const connection = await pool.getConnection();
    
    // users 테이블
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role ENUM('user', 'admin') DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_username (username),
        INDEX idx_email (email)
      )
    `);
    
    // login_logs 테이블
    await connection.query(`
      CREATE TABLE IF NOT EXISTS login_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        username VARCHAR(50),
        login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip_address VARCHAR(50),
        user_agent TEXT,
        server_name VARCHAR(255),
        status ENUM('success', 'failed') DEFAULT 'success',
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
        INDEX idx_user_id (user_id),
        INDEX idx_login_time (login_time)
      )
    `);
    
    // request_logs 테이블
    await connection.query(`
      CREATE TABLE IF NOT EXISTS request_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NULL,
        username VARCHAR(50) NULL,
        server_name VARCHAR(255),
        server_ip VARCHAR(50),
        request_path VARCHAR(255),
        request_method VARCHAR(10),
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
        INDEX idx_timestamp (timestamp)
      )
    `);
    
    connection.release();
    
    // 기본 admin 계정 생성
    await createDefaultAdmin();
    
    logger.info('데이터베이스 연결 및 테이블 생성 완료');
  } catch (error) {
    logger.error('데이터베이스 초기화 실패', { error: error.message });
  }
}

// 기본 admin 계정 생성
async function createDefaultAdmin() {
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', ['admin']);
    
    if (rows.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123!', 10);
      await pool.query(
        'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
        ['admin', 'admin@example.com', hashedPassword, 'admin']
      );
      logger.info('기본 admin 계정 생성 완료', { username: 'admin' });
    }
  } catch (error) {
    logger.error('Admin 계정 생성 실패', { error: error.message });
  }
}

// JWT 인증 미들웨어
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: '인증 토큰이 필요합니다' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: '유효하지 않은 토큰입니다' });
    }
    req.user = user;
    next();
  });
}

// Admin 권한 확인
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: '관리자 권한이 필요합니다' });
  }
  next();
}

// 요청 로깅 미들웨어
app.use((req, res, next) => {
  const serverInfo = getServerInfo();
  const startTime = Date.now();
  
  let userId = null;
  let username = null;
  
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      userId = decoded.userId;
      username = decoded.username;
    } catch (err) {}
  }

  // 응답 완료 시 로깅
  res.on('finish', () => {
    const responseTime = Date.now() - startTime;
    
    logger.info('API Request', {
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      responseTime: `${responseTime}ms`,
      userId,
      username,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      server: serverInfo.hostname
    });
  });
  
  if (pool) {
    pool.query(
      'INSERT INTO request_logs (user_id, username, server_name, server_ip, request_path, request_method) VALUES (?, ?, ?, ?, ?, ?)',
      [userId, username, serverInfo.hostname, serverInfo.ip, req.path, req.method]
    ).catch(err => logger.error('로그 저장 실패', { error: err.message }));
  }
  
  next();
});

// Swagger UI
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs, {
  customCss: '.swagger-ui .topbar { display: none }',
  customSiteTitle: "Backend API Docs"
}));

// ===== API 엔드포인트 =====

/**
 * @swagger
 * /healthz:
 *   get:
 *     summary: ALB 헬스체크 엔드포인트
 *     tags: [Health]
 *     responses:
 *       200:
 *         description: 서버 정상
 */
app.get('/healthz', (req, res) => {
  res.status(200).send('healthy');
});

/**
 * @swagger
 * /health:
 *   get:
 *     summary: 서버 상태 확인
 *     tags: [Health]
 *     responses:
 *       200:
 *         description: 서버 상태 정보
 */
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

/**
 * @swagger
 * /api/server-info:
 *   get:
 *     summary: 서버 정보 조회
 *     tags: [Server]
 *     responses:
 *       200:
 *         description: 서버 상세 정보
 */
app.get('/api/server-info', (req, res) => {
  res.json(getServerInfo());
});

/**
 * @swagger
 * /api/db/health:
 *   get:
 *     summary: 데이터베이스 상태 확인
 *     tags: [Database]
 *     responses:
 *       200:
 *         description: DB 연결 상태
 */
app.get('/api/db/health', async (req, res) => {
  if (!pool) {
    return res.json({
      status: 'disconnected',
      host: dbConfig.host,
      connections: 0,
      responseTime: 'N/A'
    });
  }

  const startTime = Date.now();
  
  try {
    const connection = await pool.getConnection();
    const responseTime = Date.now() - startTime;
    
    const [rows] = await connection.query('SHOW STATUS LIKE "Threads_connected"');
    const connections = rows[0] ? parseInt(rows[0].Value) : 0;
    
    connection.release();
    
    logger.info('DB Health Check', { status: 'connected', responseTime: `${responseTime}ms` });
    
    res.json({
      status: 'connected',
      host: dbConfig.host,
      connections: connections,
      responseTime: responseTime + 'ms',
      database: dbConfig.database
    });
  } catch (error) {
    logger.error('DB Health Check Failed', { error: error.message });
    res.status(500).json({
      status: 'error',
      host: dbConfig.host,
      connections: 0,
      responseTime: 'N/A',
      error: error.message
    });
  }
});

// ===== 인증 API =====

/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: 회원가입
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - email
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *                 example: testuser
 *               email:
 *                 type: string
 *                 example: test@example.com
 *               password:
 *                 type: string
 *                 example: password123
 *     responses:
 *       201:
 *         description: 회원가입 성공
 *       400:
 *         description: 잘못된 요청
 *       409:
 *         description: 이미 존재하는 사용자
 */
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({ error: '모든 필드를 입력해주세요' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: '비밀번호는 최소 6자 이상이어야 합니다' });
    }
    
    const [existing] = await pool.query(
      'SELECT * FROM users WHERE username = ? OR email = ?',
      [username, email]
    );
    
    if (existing.length > 0) {
      logger.warn('회원가입 실패 - 중복 사용자', { username, email });
      return res.status(409).json({ error: '이미 존재하는 사용자명 또는 이메일입니다' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const [result] = await pool.query(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username, email, hashedPassword]
    );
    
    logger.info('회원가입 성공', { userId: result.insertId, username });
    
    res.status(201).json({
      message: '회원가입이 완료되었습니다',
      userId: result.insertId,
      username: username
    });
  } catch (error) {
    logger.error('회원가입 에러', { error: error.message });
    res.status(500).json({ error: '회원가입 처리 중 오류가 발생했습니다' });
  }
});

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: 로그인
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *                 example: admin
 *               password:
 *                 type: string
 *                 example: admin123!
 *     responses:
 *       200:
 *         description: 로그인 성공
 *       401:
 *         description: 인증 실패
 */
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const serverInfo = getServerInfo();
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];
    
    const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    
    if (users.length === 0) {
      await pool.query(
        'INSERT INTO login_logs (username, login_time, ip_address, user_agent, server_name, status) VALUES (?, NOW(), ?, ?, ?, ?)',
        [username, ipAddress, userAgent, serverInfo.hostname, 'failed']
      );
      
      logger.warn('로그인 실패 - 사용자 없음', { username, ip: ipAddress });
      
      return res.status(401).json({ error: '사용자명 또는 비밀번호가 올바르지 않습니다' });
    }
    
    const user = users[0];
    const isValidPassword = await bcrypt.compare(password, user.password);
    
    if (!isValidPassword) {
      await pool.query(
        'INSERT INTO login_logs (user_id, username, login_time, ip_address, user_agent, server_name, status) VALUES (?, ?, NOW(), ?, ?, ?, ?)',
        [user.id, username, ipAddress, userAgent, serverInfo.hostname, 'failed']
      );
      
      logger.warn('로그인 실패 - 잘못된 비밀번호', { username, ip: ipAddress });
      
      return res.status(401).json({ error: '사용자명 또는 비밀번호가 올바르지 않습니다' });
    }
    
    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    await pool.query(
      'INSERT INTO login_logs (user_id, username, login_time, ip_address, user_agent, server_name, status) VALUES (?, ?, NOW(), ?, ?, ?, ?)',
      [user.id, username, ipAddress, userAgent, serverInfo.hostname, 'success']
    );
    
    logger.info('로그인 성공', { userId: user.id, username, ip: ipAddress, server: serverInfo.hostname });
    
    res.json({
      message: '로그인 성공',
      token: token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    logger.error('로그인 에러', { error: error.message });
    res.status(500).json({ error: '로그인 처리 중 오류가 발생했습니다' });
  }
});

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: 로그아웃
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: 로그아웃 성공
 */
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  logger.info('로그아웃', { username: req.user.username });
  res.json({ message: '로그아웃 되었습니다' });
});

/**
 * @swagger
 * /api/auth/me:
 *   get:
 *     summary: 현재 사용자 정보 조회
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: 사용자 정보
 */
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.query(
      'SELECT id, username, email, role, created_at FROM users WHERE id = ?',
      [req.user.userId]
    );
    
    if (users.length === 0) {
      return res.status(404).json({ error: '사용자를 찾을 수 없습니다' });
    }
    
    res.json(users[0]);
  } catch (error) {
    logger.error('사용자 정보 조회 실패', { error: error.message });
    res.status(500).json({ error: '사용자 정보 조회 실패' });
  }
});

// ===== 관리자 API =====

/**
 * @swagger
 * /api/admin/login-logs:
 *   get:
 *     summary: 로그인 기록 조회 (관리자 전용)
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 100
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [success, failed]
 *     responses:
 *       200:
 *         description: 로그인 기록 목록
 */
app.get('/api/admin/login-logs', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const status = req.query.status;
    
    let query = 'SELECT * FROM login_logs';
    let params = [];
    
    if (status) {
      query += ' WHERE status = ?';
      params.push(status);
    }
    
    query += ' ORDER BY login_time DESC LIMIT ?';
    params.push(limit);
    
    const [logs] = await pool.query(query, params);
    
    res.json({
      total: logs.length,
      logs: logs
    });
  } catch (error) {
    logger.error('로그인 기록 조회 에러', { error: error.message });
    res.status(500).json({ error: '로그인 기록 조회 실패' });
  }
});

/**
 * @swagger
 * /api/admin/users:
 *   get:
 *     summary: 사용자 목록 조회 (관리자 전용)
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: 사용자 목록
 */
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [users] = await pool.query(
      'SELECT id, username, email, role, created_at, updated_at FROM users ORDER BY created_at DESC'
    );
    
    res.json({
      total: users.length,
      users: users
    });
  } catch (error) {
    logger.error('사용자 목록 조회 실패', { error: error.message });
    res.status(500).json({ error: '사용자 목록 조회 실패' });
  }
});

/**
 * @swagger
 * /api/admin/login-stats:
 *   get:
 *     summary: 로그인 통계 조회 (관리자 전용)
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: 로그인 통계
 */
app.get('/api/admin/login-stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [stats] = await pool.query(`
      SELECT 
        u.username,
        u.email,
        COUNT(CASE WHEN ll.status = 'success' THEN 1 END) as successful_logins,
        COUNT(CASE WHEN ll.status = 'failed' THEN 1 END) as failed_logins,
        MAX(ll.login_time) as last_login
      FROM users u
      LEFT JOIN login_logs ll ON u.id = ll.user_id
      GROUP BY u.id, u.username, u.email
      ORDER BY successful_logins DESC
    `);
    
    res.json({ statistics: stats });
  } catch (error) {
    logger.error('로그인 통계 조회 실패', { error: error.message });
    res.status(500).json({ error: '로그인 통계 조회 실패' });
  }
});

/**
 * @swagger
 * /api/test:
 *   get:
 *     summary: 테스트 요청 (인증 필요)
 *     tags: [Test]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: 테스트 성공
 */
app.get('/api/test', authenticateToken, async (req, res) => {
  const startTime = Date.now();
  const serverInfo = getServerInfo();
  const responseTime = Date.now() - startTime;
  
  res.json({
    message: '테스트 요청 처리 완료',
    server: serverInfo.hostname,
    ip: serverInfo.ip,
    responseTime: responseTime + 'ms',
    timestamp: new Date().toISOString(),
    user: req.user.username
  });
});

/**
 * @swagger
 * /api/logs:
 *   get:
 *     summary: 요청 로그 조회 (관리자 전용)
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 50
 *     responses:
 *       200:
 *         description: 요청 로그 목록
 */
app.get('/api/logs', authenticateToken, requireAdmin, async (req, res) => {
  if (!pool) {
    return res.status(503).json({ error: 'Database not available' });
  }

  try {
    const limit = parseInt(req.query.limit) || 50;
    const [rows] = await pool.query(
      'SELECT * FROM request_logs ORDER BY timestamp DESC LIMIT ?',
      [limit]
    );
    
    res.json({
      total: rows.length,
      logs: rows
    });
  } catch (error) {
    logger.error('로그 조회 실패', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// 에러 핸들링
app.use((err, req, res, next) => {
  logger.error('서버 에러', { error: err.message, stack: err.stack });
  res.status(500).json({ 
    error: 'Internal Server Error',
    message: err.message 
  });
});

// 404 핸들링
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Not Found',
    path: req.path 
  });
});

// 서버 시작
async function startServer() {
  await initializeDatabase();
  
  app.listen(PORT, '0.0.0.0', () => {
    const serverInfo = getServerInfo();
    logger.info('백엔드 서버 시작', {
      port: PORT,
      hostname: serverInfo.hostname,
      ip: serverInfo.ip,
      swagger: `http://localhost:${PORT}/api-docs`,
      cloudwatch: process.env.AWS_REGION ? 'enabled' : 'disabled'
    });
    console.log('=================================');
    console.log('🚀 백엔드 서버 시작');
    console.log(`📍 포트: ${PORT}`);
    console.log(`🖥️  호스트: ${serverInfo.hostname}`);
    console.log(`🌐 IP: ${serverInfo.ip}`);
    console.log(`📚 Swagger: http://localhost:${PORT}/api-docs`);
    console.log(`📊 CloudWatch: ${process.env.AWS_REGION ? 'Enabled' : 'Disabled'}`);
    console.log('=================================');
  });
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM 신호 수신, 서버 종료 중');
  if (pool) {
    await pool.end();
  }
  process.exit(0);
});

startServer();