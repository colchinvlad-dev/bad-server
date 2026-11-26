import rateLimit from 'express-rate-limit'

// Общий rate limiter для защиты от DDoS/перегрузки большим числом запросов.
// Против злоупотреблений на авторизации: login/register чувствительны к брутфорсу.
export const generalLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 минута
    max: 300, // не более 300 запросов в минуту с одного IP
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: 'Слишком много запросов, попробуйте позже',
    },
})

export const authLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 20, // не более 20 попыток входа/регистрации в минуту
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: 'Слишком много попыток входа, попробуйте позже',
    },
})