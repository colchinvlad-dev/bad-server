import { CookieOptions } from 'express'
import ms from 'ms'

export const { PORT = '3000' } = process.env
export const { DB_ADDRESS = 'mongodb://127.0.0.1:27017/weblarek' } = process.env
// Разрешённые origin для CORS (через запятую). По умолчанию только локальная разработка.
export const ALLOWED_ORIGINS = (
    process.env.ORIGIN_ALLOW || 'http://localhost:5173'
)
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean)

// Значения для разработки; в production секреты обязаны приходить из окружения.
const isProduction = process.env.NODE_ENV === 'production'

const resolveSecret = (name: string, fallback: string) => {
    const value = process.env[name]
    if (isProduction && (!value || value === fallback)) {
        throw new Error(
            `${name} обязателен в production — задайте надёжный секрет в .env`
        )
    }
    return value || fallback
}

export const ACCESS_TOKEN = {
    secret: resolveSecret(
        'AUTH_ACCESS_TOKEN_SECRET',
        'dev-access-token-secret-change-me'
    ),
    expiry: process.env.AUTH_ACCESS_TOKEN_EXPIRY || '10m',
}
export const REFRESH_TOKEN = {
    secret: resolveSecret(
        'AUTH_REFRESH_TOKEN_SECRET',
        'dev-refresh-token-secret-change-me'
    ),
    expiry: process.env.AUTH_REFRESH_TOKEN_EXPIRY || '7d',
    cookie: {
        name: process.env.REFRESH_COOKIE_NAME || 'refreshToken',
        options: {
            httpOnly: true,
            sameSite: 'strict',
            secure: isProduction,
            maxAge: ms(process.env.AUTH_REFRESH_TOKEN_EXPIRY || '7d'),
            path: '/',
        } as CookieOptions,
    },
}

export const CSRF_TOKEN = {
    cookie: {
        // Имя cookie по контракту ревьюерских тестов
        name: process.env.CSRF_COOKIE_NAME || '_csrf',
        options: {
            httpOnly: false,
            sameSite: 'strict',
            secure: isProduction,
            path: '/',
        } as CookieOptions,
    },
    // Заголовок, в котором клиент возвращает CSRF-токен
    header: 'x-csrf-token',
}
