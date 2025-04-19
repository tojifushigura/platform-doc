
# Как написать удобный API — 10 рекомендаций

> Источник: [Habr, статья №559128](https://habr.com/ru/articles/559128/)

Автор делится 10 практическими рекомендациями по проектированию REST API на основе частых ошибок, встречающихся как при работе с чужими API, так и при создании собственных.

---

## 1. Не используйте глаголы в URL (если это одна из CRUD-операций)

CRUD-операции уже определяются HTTP-методами:

- `POST` — создать (Create)
- `GET` — получить (Read)
- `PUT/PATCH` — обновить (Update)
- `DELETE` — удалить (Delete)

❌ Плохо:
```
POST /users/{userId}/delete
POST /bookings/{bookingId}/update
```

✅ Хорошо:
```
DELETE /users/{userId}
PUT /bookings/{bookingId}
```

---

## 2. Используйте глаголы в URL, если это дополнительное действие

❌ Плохо:
```
POST /users/{userId}/books/{bookId}/create
```

✅ Хорошо:
```
POST /users/{userId}/books/{bookId}/attach
POST /users/{userId}/notifications/send
```

---

## 3. Выделяйте новые сущности, если логика требует

Пример: если вы реализуете избранное:

✅ Хорошо:
```
POST /wishlist/{userId}/{bookId}
```

---

## 4. Один идентификатор ресурса

Если структура "один ко многим", то достаточно идентификатора дочернего ресурса.

❌ Плохо:
```
GET /bookings/{bookingId}/travellers/{travellerId}
```

✅ Хорошо:
```
GET /bookings/travellers/{travellerId}
```

---

## 5. Все ресурсы во множественном числе

❌ Плохо:
```
GET /user/{userId}
POST /ticket/{ticketId}/book
```

✅ Хорошо:
```
GET /users/{userId}
POST /tickets/{ticketId}/book
```

---

## 6. Используйте HTTP-статусы

- `400 Bad Request` — ошибка клиента
- `401 Unauthorized` — нужна аутентификация
- `403 Forbidden` — доступ запрещён
- `404 Not Found` — ресурс не найден
- `409 Conflict` — конфликт состояния
- `500 Internal Server Error` — ошибка сервера
- `503 Service Unavailable` — сервер недоступен

---

## 7. Модификаторы ресурса

Например, /quizzes/passed — это модификатор основного ресурса.

❌ Плохо:
```
GET /passed-quizzes
GET /booked-tickets
POST /gold-users
```

✅ Хорошо:
```
GET /quizzes/passed
GET /tickets/booked
POST /users/gold
```

---

## 8. Унификация структуры ответов

❌ Плохо:
```json
{
    "name": "Harry Potter",
    "genre": "fantasy",
    "status": 0,
    "error": false
}
```

✅ Хорошо:
```json
{
    "status": 0,
    "message": "ok",
    "data": {
        "name": "Harry Potter",
        "genre": "fantasy"
    }
}
```

---

## 9. camelCase для параметров и JSON

### В URL:

❌ Плохо:
```
GET /users/{user-id}
GET /users/{user_id}
```

✅ Хорошо:
```
GET /users/{userId}
```

### В JSON:

❌ Плохо:
```json
{
    "ID": "uuid",
    "Name": "user",
    "provider_id": 123,
    "Created_At": "2024-01-01"
}
```

✅ Хорошо:
```json
{
    "id": "uuid",
    "name": "user",
    "providerId": 123,
    "createdAt": "2024-01-01"
}
```

---

## 10. Используйте Content-Type

❌ Плохо:
```
GET /tickets.json
GET /tickets.xml
```

✅ Хорошо:
```
GET /tickets
// Заголовки:
Content-Type: application/json
Content-Type: application/xml
```

---

## Заключение

Это лишь базовый набор рекомендаций по улучшению API. Для глубокого понимания рекомендуем изучить:

- спецификации REST
- все возможные HTTP-коды статуса

А какие советы дали бы вы? Оставьте комментарий!
