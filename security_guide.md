
# Руководство по обеспечению безопасности веб-приложения на React + PHP + MySQL

Данный документ представляет собой подробное руководство по внедрению современных мер защиты API и пользовательских данных для веб-приложения. Его цель — защитить ваш сервис от SQL-инъекций, перехвата трафика (MITM), кражи токенов, брутфорса, XSS, CSRF, а также реализовать надёжную авторизацию и шифрование.

---

## 🔐 Зачем нужна безопасность

Веб-приложения ежедневно обрабатывают конфиденциальные данные: пароли, телефоны, e-mail пользователей. Без защиты возможны:
- кража аккаунтов,
- утечка персональных данных,
- подмена запросов или кража токенов,
- удаление/изменение данных злоумышленником.

Чтобы этого не допустить — требуется внедрение **многоуровневой защиты**.

---

## 1. Защита API ключами

**Что это:** Все запросы к API требуют `X-API-KEY`, генерируемого на сервере.

**Почему:** Ограничивает доступ к API извне, позволяет различать легальные/нелегальные вызовы.

**Пример:**

```php
$headers = getallheaders();
if ($headers['X-API-KEY'] !== 'super_secret_key') {
    http_response_code(403);
    exit('Access Denied');
}
```

---

## 2. Протокол HTTPS + HSTS

**Что это:** Шифрование данных между клиентом и сервером + указание браузеру работать только по HTTPS.

**Почему:** Исключает MITM-атаки, делает невозможной подмену трафика.

**.htaccess:**

```apache
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
```

---

## 3. Защита от SQL-инъекций

**Что это:** Подготовленные выражения (`prepared statements`) в PDO или mysqli.

**Почему:** Исключает внедрение SQL-кода через ввод пользователя.

**Пример:**

```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");
$stmt->execute(['email' => $email]);
```

---

## 4. Защита от MITM и кражи сессий

**Решения:**
- HTTPS + HSTS
- JWT-токены с истечением
- Certificate Pinning (для React Native)

**React Native:**

```js
fetch("https://secure.api.com", {
  sslPinning: { certs: ["api_cert"] }
});
```

---

## 5. Брутфорс и CSRF

### Брутфорс:
Ограничьте число попыток входа (Redis, файл, БД).

```php
$key = 'login:' . $_SERVER['REMOTE_ADDR'];
$attempts = $redis->incr($key);
if ($attempts == 1) $redis->expire($key, 900); // 15 мин
if ($attempts > 5) exit('Too many attempts');
```

### CSRF:
```php
session_start();
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
```

HTML:
```html
<input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
```

---

## 6. Защита от DoS/DDoS

**На уровне сервера:**
- Cloudflare proxy
- Fail2Ban / iptables
- Web Application Firewall (IONOS, ModSecurity)

**Программно:**
- Ограничение количества запросов (Rate Limit)
- Проверка User-Agent / Referer / Origin

---

## 7. Хеширование паролей — Argon2

**Почему:** Самый защищённый алгоритм хеширования паролей, встроен в PHP.

```php
$hash = password_hash($password, PASSWORD_ARGON2ID);
```

Проверка:
```php
if (password_verify($input, $hash)) { ... }
```

---

## 8. JWT (JSON Web Token)

**Что это:** Стандартизированный формат для безопасной авторизации.

```php
$token = JWT::encode(['id' => $userId], 'secret', 'HS256');
```

Проверка:
```php
$decoded = JWT::decode($token, new Key('secret', 'HS256'));
```

---

## 9. Авторизация: роли и права

**На уровне API:**

```php
if ($user->role !== 'admin') {
    http_response_code(403);
    exit('Insufficient permissions');
}
```

---

## 10. Логирование и мониторинг

- Логировать все неудачные входы
- При 5+ попытках — блокировка IP на 15 минут

```php
if ($failed_logins >= 5) {
  $ban_until = time() + 900;
  // сохранить в Redis или MySQL
}
```

### IDS/IPS:
- Использовать Fail2Ban + iptables
- Мониторинг через лог-файлы (например, `/var/log/auth.log`)

---

## ✅ Финальный чек-лист

- [x] Все запросы по HTTPS
- [x] Хеширование паролей через Argon2id
- [x] JWT-токены
- [x] Валидация SQL
- [x] CORS, CSP, XSS фильтрация
- [x] CSRF-токены
- [x] Блокировка брутфорса
- [x] API по ключам
- [x] Логирование попыток
- [x] Защита через WAF/Cloudflare
