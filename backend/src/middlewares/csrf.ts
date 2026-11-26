import { NextFunction, Request, Response } from 'express'
import crypto from 'crypto'
import { CSRF_TOKEN } from '../config'
import ForbiddenError from '../errors/forbidden-error'

// Endpoint-ы, которые сами ВЫДАЮТ CSRF-токен (login/register/refresh)
// выполняются до существования cookie, поэтому проверка для них отключается.
const EXEMPT_PATHS: { method: string; path: RegExp }[] = [
    { method: 'POST', path: /^\/auth\/(login|register|refresh)$/ },
]

// Double-Submit CSRF: токен выдаётся в не-httpOnly cookie, а в мутирующих
// запросах возвращается в заголовке X-CSRF-Token. Сервер сравнивает значения.
export function csrfProtection() {
    return (req: Request, _res: Response, next: NextFunction) => {
        const safeMethods = ['GET', 'HEAD', 'OPTIONS']
        if (safeMethods.includes(req.method)) {
            return next()
        }

        const exempt = EXEMPT_PATHS.some(
            ({ method, path }) => method === req.method && path.test(req.path)
        )
        if (exempt) {
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

// Выдаёт CSRF-токен для нового пользователя (вызывается при login/register/refresh)
export function issueCsrfToken(_req: Request, res: Response) {
    const token = crypto.randomBytes(32).toString('hex')
    res.cookie(CSRF_TOKEN.cookie.name, token, CSRF_TOKEN.cookie.options)
    return token
}