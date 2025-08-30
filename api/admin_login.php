<?php
// 1. 会话安全配置（必须放在 session_start() 之前，且无任何输出）
ini_set('session.cookie_secure', 'On');       // 仅HTTPS传输Cookie（生产环境启用，本地HTTP可设为Off）
ini_set('session.cookie_httponly', 'On');     // 禁止JS访问Cookie，防XSS
ini_set('session.cookie_samesite', 'Strict'); // 严格同源策略，防CSRF
ini_set('session.cookie_lifetime', 0);        // 会话结束后Cookie失效（关闭浏览器即删）
ini_set('session.gc_maxlifetime', 3600);      // Session 有效期1小时（秒）
ini_set('session.regenerate_id', 'On');       // 每次请求重置Session ID，防固定攻击

// 初始化Session（确保无任何输出后执行）
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once 'db_connect.php';

// --- 2. 防止反复尝试登录的逻辑 ---
$clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown'; // 兼容无IP的极端情况
$maxAttempts = 3;         // 最大失败次数
$lockTime = 900;          // 锁定时间（15分钟 = 900秒）

// 初始化登录失败记录的Session（键：客户端IP，值：[失败次数, 首次失败时间]）
if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = [];
}

// 检查当前IP是否被锁定
if (isset($_SESSION['login_attempts'][$clientIp])) {
    $attemptData = $_SESSION['login_attempts'][$clientIp];
    $attemptCount = $attemptData[0];
    $firstFailTime = $attemptData[1];

    // 锁定未过期：拒绝登录请求
    if ($attemptCount >= $maxAttempts && (time() - $firstFailTime) < $lockTime) {
        $remainingTime = $lockTime - (time() - $firstFailTime);
        http_response_code(429); // 429 = 请求过于频繁
        echo json_encode([
            'success' => false,
            'message' => "登录失败次数过多，请" . intval($remainingTime / 60) . "分钟后再试"
        ]);
        exit;
    }

    // 锁定已过期：重置该IP的失败记录
    if ((time() - $firstFailTime) >= $lockTime) {
        unset($_SESSION['login_attempts'][$clientIp]);
    }
}

// --- 3. 限制请求方法为POST ---
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405); // 405 = 方法不允许
    echo json_encode(['success' => false, 'message' => '仅支持POST方法']);
    exit;
}

// --- 4. 获取并验证表单数据 ---
$username = trim($_POST['admin_username'] ?? '');
$password = trim($_POST['admin_password'] ?? '');

// 空值校验
if (empty($username) || empty($password)) {
    echo json_encode(['success' => false, 'message' => '用户名和密码不能为空']);
    exit;
}

try {
    // --- 5. 数据库查询与密码验证 ---
    // 仅查询需要的字段（避免敏感字段暴露），且使用预处理防SQL注入
    $stmt = $pdo->prepare("SELECT id, username, password, role FROM admins WHERE username = ?");
    $stmt->execute([$username]);
    $admin = $stmt->fetch(PDO::FETCH_ASSOC);

    // 验证失败：累加失败次数并返回提示
    if (!$admin || !password_verify($password, $admin['password'])) {
        // 记录失败次数：首次失败则存“次数1+当前时间”，否则次数+1
        if (!isset($_SESSION['login_attempts'][$clientIp])) {
            $_SESSION['login_attempts'][$clientIp] = [1, time()];
        } else {
            $_SESSION['login_attempts'][$clientIp][0]++;
        }

        // 计算剩余可尝试次数
        $remainingAttempts = $maxAttempts - $_SESSION['login_attempts'][$clientIp][0];
        $msg = $remainingAttempts > 0 
            ? "用户名或密码错误，还剩{$remainingAttempts}次机会" 
            : "登录失败次数过多，请15分钟后再试";

        echo json_encode(['success' => false, 'message' => $msg]);
        exit;
    }

    // --- 6. 登录成功：重置失败记录 + 初始化管理员Session ---
    // 重置当前IP的失败记录（登录成功后解锁）
    if (isset($_SESSION['login_attempts'][$clientIp])) {
        unset($_SESSION['login_attempts'][$clientIp]);
    }

    // 重置Session ID（防Session固定攻击，关键步骤）
    session_regenerate_id(true);

    // 存储管理员核心信息到Session（仅存必要字段，不存密码）
    $_SESSION['admin'] = [
        'id' => $admin['id'],
        'username' => $admin['username'],
        'role' => $admin['role'],
        'login_time' => time() // 记录登录时间，可用于后续超时判断
    ];

    // 返回成功响应
    echo json_encode([
        'success' => true,
        'message' => '登录成功，正在跳转...',
        'role' => $admin['role'] // 返回角色，供前端权限控制
    ]);
    exit;

} catch (PDOException $e) {
    // --- 7. 捕获数据库异常（生产环境建议隐藏具体错误信息） ---
    http_response_code(500); // 500 = 服务器内部错误
    echo json_encode([
        'success' => false,
        'message' => '服务器异常，请稍后再试' // 调试时可改为 $e->getMessage() 查看具体错误
    ]);
    exit;
}
