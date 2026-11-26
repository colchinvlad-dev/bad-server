import { NextFunction, Request, Response } from 'express'
import crypto from 'crypto'
import { CSRF_TOKEN } from '../config'
import ForbiddenError from '../errors/forbidden-error'

// Double-Submit CSRF: токен выдаётся в не-httpOnly cookie `_csrf`, а в
// мутирующих запросах возвращается в заголовке X-CSRF-Token. Сервер сравнивает
// значения cookie и заголовка, что исключает CSRF-атаки из других сайтов.
export function csrfProtection() {
    return (req: Request, _res: Response, next: NextFunction) => {
        const safeMethods = ['GET', 'HEAD', 'OPTIONS']
        if (safeMethods.includes(req.method)) {
            return next()
        }

        const cookieToken = req.cookies?.[CSRF_TOKEN.cookie.name]
        const headerToken = req.get(CSRF_TOKEN.header)

        if (!cookieToken || !headerToken || cookieToken !== headerToken) {
            return next(new ForbiddenError('CSRF-проверка не пройдена'))
        }

        return next()
    }
}

// Выдаёт CSRF-токен: кладёт его в не-httpOnly cookie `_csrf` и возвращает.
export function issueCsrfToken(_req: Request, res: Response) {
    const token = crypto.randomBytes(32).toString('hex')
    res.cookie(CSRF_TOKEN.cookie.name, token, CSRF_TOKEN.cookie.options)
    return token
}

// Обработчик GET /auth/csrf-token по контракту тестов: возвращает 200 с полем
// csrfToken и устанавливает cookie `_csrf`.
export function getCsrfTokenHandler(_req: Request, res: Response) {
    const csrfToken = issueCsrfToken(_req, res)
    return res.status(200).json({ csrfToken })
}