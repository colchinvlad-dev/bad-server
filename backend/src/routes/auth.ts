import { Router } from 'express'
import {
    getCurrentUser,
    getCurrentUserRoles,
    login,
    logout,
    refreshAccessToken,
    register,
    updateCurrentUser,
} from '../controllers/auth'
import { getCsrfTokenHandler } from '../middlewares/csrf'
import auth from '../middlewares/auth'

const authRouter = Router()

authRouter.get('/csrf-token', getCsrfTokenHandler)
authRouter.get('/user', auth, getCurrentUser)
authRouter.patch('/me', auth, updateCurrentUser)
authRouter.get('/user/roles', auth, getCurrentUserRoles)
authRouter.post('/login', login)
authRouter.post('/refresh', refreshAccessToken)
authRouter.post('/logout', logout)
authRouter.post('/register', register)

export default authRouter
