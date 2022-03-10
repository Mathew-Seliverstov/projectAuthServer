const UserModel = require('../models/UserModel') 
const bcrypt = require('bcrypt')
const uuid = require('uuid')
const MailService = require('./mail-service')
const TokenService = require('./token-service')
const UserDto = require('../dtos/UserDto')
const ApiError = require('../exceptions/api-error')

class UserService {
	async signup(email, password) {
		const candidate = await UserModel.findOne({email})
		if (candidate) {
			throw ApiError.BadRequest(`Пользователь с email: ${email} уже существует`)
		}
		const hashPassword = await bcrypt.hash(password, 3)
		const activationLink = uuid.v4()

		const user = await UserModel.create({email, password: hashPassword, activationLink})
		await MailService.sendActivationMail(email, `${process.env.API_URL}/api/activate/${activationLink}`)

		const userDto = new UserDto(user)
		const tokens = TokenService.generateTokens({...userDto})
		await TokenService.saveToken(userDto.id, tokens.refreshToken)

		return {...tokens, user: userDto}
	}

	async activate(activationLink) {
		const user = await UserModel.findOne({activationLink})
		if (!user) {
			throw ApiError.BadRequest('Некоректная ссылка активации')
		}
		user.isActivated = true
		await user.save()
	}

	async login(email, password) {
		const user = await UserModel.findOne({email})
		if (!user) {
			throw ApiError.BadRequest('Пользователь с таким email не найден')
		}
		const isPassEquals = await bcrypt.compare(password, user.password)
		if (!isPassEquals) {
			throw ApiError.BadRequest('Неверный пароль')
		}
		const userDto = new UserDto(user)
		const tokens = TokenService.generateTokens({...userDto})
		await TokenService.saveToken(userDto.id, tokens.refreshToken)

		return {...tokens, user: userDto}
	}

	async logout(refreshToken) {
		const token = await TokenService.removeToken(refreshToken)
		return token
	}

	async refresh(refreshToken) {
		if (!refreshToken) {
			throw ApiError.UnauthorizedError()
		}
		const userData = TokenService.validateRefreshToken(refreshToken)
		const tokenFromDb = await TokenService.findToken(refreshToken)
		if(!userData || !tokenFromDb) {
			throw ApiError.UnauthorizedError()
		}
		const user = await UserModel.findById(userData.id)
		const userDto = new UserDto(user)
		const tokens = TokenService.generateTokens({...userDto})
		await TokenService.saveToken(userDto.id, tokens.refreshToken)

		return {...tokens, user: userDto}
	}

	async getAllUsers() {
		const users = await UserModel.find()
		return users
	}
}

module.exports = new UserService()
