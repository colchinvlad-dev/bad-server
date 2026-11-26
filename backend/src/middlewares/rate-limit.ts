import { NextFunction, Request, Response } from 'express'
import rateLimit from 'express-rate-limit'

// Rate limiter настраивается через переменные окружения (как в docker-compose тестов):
//   RATE_LIMITED:          включить лимит (по умолчанию true)
//   RATE_LIMIT_POINTS:     максимум запросов в окне (по умолчанию 300)
//   RATE_LIMIT_DURATION:   длина окна в секундах (по умолчанию 60)
//   RATE_LIMIT_BLOCK:      блокировка в секундах (запасной параметр)
const isRateLimited = process.env.RATE_LIMITED !== 'false'
const POINTS = Number(process.env.RATE_LIMIT_POINTS) || 300
const DURATION = Number(process.env.RATE_LIMIT_DURATION) || 60

// Общий rate limiter против DDoS. Исключаем /auth: у них свой, более строгий,
// чтобы подготовительные логины тестов не отсекались общим окном.
export const generalLimiter = isRateLimited
    ? rateLimit({
          windowMs: DURATION * 1000,
          max: POINTS,
          standardHeaders: true,
          legacyHeaders: false,
          skip: (req: Request) => req.path.startsWith('/auth'),
          message: {
              success: false,
              message: 'Слишком много запросов, попробуйте позже',
          },
      })
    : (_req: Request, _res: Response, next: NextFunction) => next()

// Лимит на авторизацию (login/register/refresh) против брутфорса.
export const authLimiter = isRateLimited
    ? rateLimit({
          windowMs: DURATION * 1000,
          max: Math.max(20, POINTS),
          standardHeaders: true,
          legacyHeaders: false,
          message: {
              success: false,
              message: 'Слишком много попыток входа, попробуйте позже',
          },
      })
    : (_req: Request, _res: Response, next: NextFunction) => next()