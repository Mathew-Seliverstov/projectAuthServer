const express = require('express')
const Router = express.Router
const UserController = require('../controllers/user-controller')
const router = new Router()
const {body} = require('express-validator')
const authMiddleware = require('../middlewares/auth-middleware')

router.post(
	'/signup', 
	body('email').isEmail(),
	body('password').isLength({min: 4, max: 32}),
	UserController.signup
)
router.post('/login', UserController.login)
router.post('/logout', UserController.logout)
router.get('/activate/:link', UserController.activate)
router.get('/refresh', UserController.refresh)
router.get('/users', authMiddleware, UserController.getUsers)

module.exports = router
