
# Руководство по Безопасности Веб-приложения (React + PHP + MySQL)

Это руководство подготовлено для команды разработчиков, чтобы обеспечить **высокий уровень защиты веб-приложения**, написанного на React (React Native) и PHP (бэкенд), с использованием базы данных MySQL. Включены примеры и инструкции по реализации.

---

## 1. Транспортный уровень: HTTPS и защита соединения

### ✅ Всегда использовать HTTPS

**Цель:** Защитить данные от перехвата в пути между клиентом и сервером.

**Реализация:**
- Все запросы к `fetch` или Axios должны начинаться с `https://`
- На хостинге IONOS включить SSL-сертификат и сделать 301 редирект с `http` → `https`

```apacheconf
# .htaccess
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
```

### ✅ Включить HSTS (HTTP Strict Transport Security)

**Цель:** Запретить браузеру использовать HTTP.

```apacheconf
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
```

### ✅ Certificate Pinning (для React Native)

**Цель:** Исключить MITM-атаки при фальшивом HTTPS.

**Пример (react-native-ssl-pinning):**

```bash
npm install react-native-ssl-pinning
```

```js
import {fetch} from 'react-native-ssl-pinning';

fetch("https://app.domain.com/api", {
  method: "GET",
  sslPinning: {
    certs: ["domain_cert"]  // файл domain_cert.cer в android/app/src/main/assets/
  }
});
```

---

## 2. Хеширование паролей: Argon2

### ✅ Использовать `password_hash()` с `ARGON2ID`

```php
$hash = password_hash($password, PASSWORD_ARGON2ID);
```

### ✅ Проверка пароля

```php
if (password_verify($input, $hash)) {
    // Успешно
}
```

---

## 3. API: Авторизация и защита

### ✅ JWT и заголовок Authorization

**Генерация:**
```php
use Firebase\JWT\JWT;
$jwt = JWT::encode(['userId'=>1], 'SECRET_KEY', 'HS256');
```

**Проверка:**
```php
$token = str_replace('Bearer ', '', $_SERVER['HTTP_AUTHORIZATION']);
$data = JWT::decode($token, new Key('SECRET_KEY', 'HS256'));
```

---

## 4. HTTP Security Headers

### ✅ Полная конфигурация в `.htaccess`

```apacheconf
# Безопасные заголовки
Header set X-Content-Type-Options "nosniff"
Header set X-XSS-Protection "1; mode=block"
Header always set X-Frame-Options "SAMEORIGIN"
Header set Referrer-Policy "strict-origin-when-cross-origin"
Header set Permissions-Policy "geolocation=(), microphone=()"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
```

---

## 5. Аутентификация и управление сессиями

### ✅ Хранение токена в SecureStore (React Native)

```js
import * as SecureStore from 'expo-secure-store';

await SecureStore.setItemAsync('userToken', token);
const token = await SecureStore.getItemAsync('userToken');
```

---

## 6. Защита от атак

### ✅ SQL-инъекции

**Использовать PDO и подготовленные запросы:**

```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");
$stmt->execute(['email' => $email]);
```

### ✅ XSS

**Фильтрация вывода HTML:**

```php
echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8');
```

### ✅ CSRF (для форм)

```php
// PHP: генерация токена
session_start();
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
```

```html
<input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
```

### ✅ CSP (Content Security Policy)

```apacheconf
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'"
```

### ✅ CORS: ограничение источников

```php
header("Access-Control-Allow-Origin: https://yourapp.com");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Authorization, Content-Type");
```

---

## 7. Перехват трафика и защита

- Используйте HTTPS для всех API.
- Делайте проверку API-ключей или сигнатур (HMAC).
- Никогда не храните чувствительные токены в AsyncStorage — только SecureStore.

---

## 8. Дополнительно

### 📌 Рейтлимитинг на PHP (пример с Redis)

```php
$key = "login_attempts:" . $_SERVER['REMOTE_ADDR'];
$attempts = $redis->incr($key);
if ($attempts == 1) $redis->expire($key, 60); // 1 минута
if ($attempts > 5) die("Too many attempts");
```

### 📌 CAPTCHA

Вставьте Google reCAPTCHA v3 на страницу регистрации:

```html
<script src="https://www.google.com/recaptcha/api.js?render=SITE_KEY"></script>
```

---

## ✅ Финальные рекомендации

1. Использовать HTTPS всегда и везде.
2. Настроить все headers в `.htaccess`
3. Пароли: только bcrypt или argon2id + соль
4. Аутентификация: JWT + SecureStore на клиенте
5. Проверка API: только с авторизацией
6. Отключить CORS и CSRF без валидации
7. Не доверяйте фронтенду, проверяйте всё на сервере

