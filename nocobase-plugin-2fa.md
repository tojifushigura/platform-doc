Отлично, давай сделаем свой простой, но рабочий плагин для 2FA (двухфакторная аутентификация) через Google Authenticator (TOTP) для **NocoBase v1.7.17**.  
Объясню кратко по шагам, а затем дам полный код и инструкции.

---

## Как это будет работать

1. **Администратор включает 2FA** — пользователь настраивает 2FA в своем профиле.
2. **Генерация QR-кода** для Google Authenticator (или аналога, например, Authy).
3. **Проверка кода** при логине.
4. **Секрет хранится в базе** (например, в отдельном поле users или через связку).
5. **Обратная совместимость**: у пользователей без 2FA ничего не меняется.

---

## Шаг 1: Выбор подхода для расширения

- В NocoBase есть свои плагины (в `packages/plugins`), они бывают как backend-only, так и fullstack.
- 2FA — это бэкенд + чуть-чуть фронта (настройка, QR, ввод кода при логине).
- Минимально: кастомный плагин с одним API-роутом и middleware.

---

## Шаг 2: Что понадобится

- **npm пакет** [`speakeasy`](https://github.com/speakeasyjs/speakeasy) — для генерации и проверки TOTP
- **npm пакет** [`qrcode`](https://github.com/soldair/node-qrcode) — для генерации QR-кода
- Для фронта используем NocoBase UI API (`registerSchema`, SchemaComponent, Modal и т.д.), либо даём raw HTML (минимально).

---

## Шаг 3: Пример структуры плагина

```
packages/plugins/nocobase-plugin-2fa/
├── src/
│   ├── index.ts           // точка входа плагина
│   ├── routes.ts          // роуты API
│   ├── middleware.ts      // middleware для проверки 2FA при логине
│   └── utils.ts           // генерация и верификация TOTP
├── package.json
└── README.md
```

---

## Шаг 4: Код плагина (backend, TypeScript)

### 1. package.json

```json
{
  "name": "nocobase-plugin-2fa",
  "version": "1.0.0",
  "main": "src/index.ts",
  "dependencies": {
    "speakeasy": "^2.0.0",
    "qrcode": "^1.5.0"
  }
}
```

### 2. src/utils.ts

```ts
import * as speakeasy from 'speakeasy';

export function generateSecret(label: string) {
  return speakeasy.generateSecret({
    name: label,
    length: 20
  });
}

export function verifyToken(secret: string, token: string) {
  return speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token,
    window: 1 // допустим 30 сек влево/вправо
  });
}

export function otpauthUrl(secret: string, label: string) {
  return `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=NocoBase`;
}
```

### 3. src/routes.ts

```ts
import { Application } from '@nocobase/server';
import * as QRCode from 'qrcode';
import { generateSecret, verifyToken, otpauthUrl } from './utils';

export default (app: Application) => {
  // Для настройки 2FA: генерация секрета и QR
  app.get('/api/2fa/setup', async (req, res) => {
    const userId = req.user?.id; // зависит от реализации авторизации
    if (!userId) return res.status(401).send('Unauthorized');

    const label = req.user.email || `user${userId}`;
    const secretObj = generateSecret(label);

    // Сохрани secret.base32 для userId (в БД)
    await app.db.getRepository('users').update({ id: userId }, { twofa_secret: secretObj.base32 });

    // QR для Google Authenticator
    const url = otpauthUrl(secretObj.base32, label);
    const qr = await QRCode.toDataURL(url);

    res.json({ secret: secretObj.base32, url, qr });
  });

  // Проверка токена
  app.post('/api/2fa/verify', async (req, res) => {
    const userId = req.user?.id;
    const { token } = req.body;
    if (!userId) return res.status(401).send('Unauthorized');
    if (!token) return res.status(400).send('No token');

    const user = await app.db.getRepository('users').findOne({ where: { id: userId } });
    if (!user?.twofa_secret) return res.status(400).send('2FA not setup');

    const isValid = verifyToken(user.twofa_secret, token);
    if (!isValid) return res.status(400).send('Invalid token');

    // Можно сохранить отметку, что 2FA пройдено (например, в сессии)
    req.session['2fa_passed'] = true;
    res.json({ ok: true });
  });
};
```

### 4. src/middleware.ts

```ts
import { Application } from '@nocobase/server';

export default (app: Application) => async (req, res, next) => {
  // Пример: проверяем, если у пользователя есть twofa_secret — требуем прохождение 2FA
  if (req.user) {
    const user = await app.db.getRepository('users').findOne({ where: { id: req.user.id } });
    if (user?.twofa_secret && !req.session['2fa_passed']) {
      return res.status(401).json({ error: '2FA required' });
    }
  }
  next();
};
```

### 5. src/index.ts

```ts
import { Plugin } from '@nocobase/server';
import routes from './routes';
import middleware from './middleware';

export default class TwoFANocoBasePlugin extends Plugin {
  async load() {
    this.app.db.table('users').addColumn({
      name: 'twofa_secret',
      type: 'string',
      allowNull: true,
    });

    // добавляем API
    routes(this.app);

    // вставляем middleware для защищённых роутов
    this.app.use(middleware(this.app));
  }
}
```

---

## Шаг 5: Настройка фронта (примерно)

- **Выводим QR** и поле для ввода токена (можно через кастомный компонент или в профиле пользователя).
- При логине (если 2FA включен), показываем модалку "Введите код из Google Authenticator".
- Можно сделать мини-страницу/модалку на UI, чтобы красиво добавить.

---

## Шаг 6: Инструкция по установке

1. Клонируй/создай директорию `packages/plugins/nocobase-plugin-2fa`.
2. Скопируй туда все исходники из примера.
3. В корне NocoBase добавь в `packages/plugins` новую строку в зависимости и в `config.json` подключи плагин.
4. Внутри директории плагина выполни:  
   ```
   npm install speakeasy qrcode
   ```
5. Перезапусти сервер NocoBase:
   ```
   npm run build
   npm run start
   ```

---

## Что дальше

- Расширить фронт (UI) — добавить настройку 2FA в профиль пользователя.
- Сделать сброс 2FA админом (на всякий случай).
- Логирование действий (включение/выключение 2FA).

---

## Пример базы данных (если fields вручную)

Добавь в модель пользователя поле `twofa_secret` (`string`, nullable).

---

## Полезные ссылки

- [Документация Speakeasy](https://github.com/speakeasyjs/speakeasy)
- [Google Authenticator TOTP](https://datatracker.ietf.org/doc/html/rfc6238)

---

### Если нужны примеры фронта или подробности — дай знать, допишу!  
**Могу сделать под любую версию, структуру и требования.**  
Пиши, если что-то не понятно, нужна адаптация под твой фронт/бэкенд.
