
# Полное руководство по безопасности приложения React + PHP + MySQL

Это документ для внедрения системы безопасной авторизации, защиты API, хеширования паролей и предотвращения атак.  
Включает подробный анализ, рекомендации и примеры кода. Все действия адаптированы под **IONOS-хостинг** и 100% работу по **HTTPS (SSL + HSTS)**.

## 🛡️ Раздел 1: Основные уязвимости

1. Нет защиты от SQL-инъекций
2. Пароли хранятся в открытом виде или через устаревший MD5
3. API доступен без авторизации
4. Хранение токенов в AsyncStorage
5. Отсутствие заголовков безопасности (CSP, CORS, X-Frame и т.п.)
6. Нет защиты от XSS, CSRF и MITM

## 🔐 Раздел 2: Рекомендации

| Область         | Меры                                                  |
|------------------|--------------------------------------------------------|
| HTTPS            | ✅ Включить SSL и редирект с HTTP                      |
| HSTS             | ✅ Прописать заголовок HSTS                            |
| Certificate pin  | ✅ Применить SSL Pinning в React Native               |
| Хеширование      | ✅ Использовать Argon2id через `password_hash`         |
| API-доступ       | ✅ Проверка `Authorization: Bearer <token>`           |
| JWT-токены       | ✅ Сессии через JWT                                    |
| CSRF/XSS         | ✅ Токены и экранирование HTML                         |
| Заголовки        | ✅ CSP, CORS, X-Frame, Permissions-Policy              |
| Хранилище клиента| ✅ Использовать SecureStore                            |

## 🔐 HTTPS + HSTS

.htaccess:
```apache
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
```

## 🔒 Certificate Pinning в React Native

```js
import {fetch} from 'react-native-ssl-pinning';

fetch("https://app.domain.com/api", {
  method: "GET",
  sslPinning: {
    certs: ["domain_cert"]  // .cer файл в assets
  }
});
```

## 🔐 Пример безопасной регистрации на PHP

```php
$hash = password_hash($password, PASSWORD_ARGON2ID);
$stmt = $pdo->prepare("INSERT INTO users (username, email, pass) VALUES (?, ?, ?)");
$stmt->execute([$username, $email, $hash]);
```

## 🔐 Проверка пароля при входе

```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE email=?");
$stmt->execute([$email]);
$user = $stmt->fetch();
if (password_verify($password, $user['pass'])) {
    $token = JWT::encode(['id'=>$user['id']], 'SECRET_KEY', 'HS256');
    echo json_encode(['status'=>true, 'token'=>$token]);
}
```

## 🔐 Заголовки безопасности (Apache)

```apache
Header set X-Frame-Options "DENY"
Header set X-Content-Type-Options "nosniff"
Header set X-XSS-Protection "1; mode=block"
Header set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Content-Security-Policy "default-src 'self';"
Header set Permissions-Policy "geolocation=(), microphone=()"
```

## 🧱 CORS

```php
header("Access-Control-Allow-Origin: https://app.xv-platform.de");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Authorization, Content-Type");
```

## 🔐 Хранилище токена в клиенте (React Native)

```js
import * as SecureStore from 'expo-secure-store';
await SecureStore.setItemAsync('userToken', token);

const token = await SecureStore.getItemAsync('userToken');
fetch(url, {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`
  }
});
```

## ⚠️ Ограничение доступа к API по ключу

```php
$headers = getallheaders();
if ($headers['X-API-KEY'] !== 'secret_key_123') {
    http_response_code(403);
    exit;
}
```

## ✅ Хеширование: что использовать

| Алгоритм | Использовать? | Причина |
|----------|----------------|---------|
| MD5      | ❌             | Слишком быстрый, легко ломается |
| bcrypt   | ✅             | Поддерживается PHP, медленный |
| Argon2id | ✅✅            | Лучший выбор: защита от GPU-атак |

## ✅ CSRF защита

```php
// генерируем токен
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
```

```html
<input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
```

## ✅ XSS защита

```php
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
```

## 📦 Финальные рекомендации

- ✅ Все запросы — только HTTPS
- ✅ API — только с JWT или HMAC
- ✅ Пароли — только через Argon2id
- ✅ Все заголовки безопасности активны
- ✅ Использовать SecureStore
- ✅ Проверки CORS/CSRF
- ✅ Все SQL-запросы через PDO prepare()
