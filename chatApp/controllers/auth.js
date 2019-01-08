const Joi = require('joi');
const httpStatus = require('http-status-codes');
const bcryptjs = require('bcryptjs')
const jwt = require('jsonwebtoken');

const User = require('../models/userModels');
const Helper = require('../Helpers/helpers');
const dbconfig = require('../config/secret');

module.exports = {
    async createUser(req, res, next) {
        console.log(req.body);
        const schema = Joi.object().keys({
            username: Joi.string().min(3).max(20).required(),
            email: Joi.string().email().required(),
            password: Joi.string().min(3).max(10).required()
        });

        const {error, value} = Joi.validate(req.body, schema);
        if(error && error.details) {
            return res.status(httpStatus.BAD_REQUEST).json({msg: error.details});
        }

        const userEmail = await User.findOne({ email: Helper.lowerCase(req.body.email) });
        if(userEmail) {
            return res.status(httpStatus.CONFLICT).json({message: 'email already exist'});
        }

        const userName = await User.findOne({ username: Helper.firstUpper(req.body.username) });
        if(userName) {
            return res.status(httpStatus.CONFLICT).json({message: 'username already exist'});
        }

        return bcryptjs.hash(value.password, 10, (err, hash) => {
            if(err) {
               return res.status(httpStatus.BAD_REQUEST).json({message: 'Error hashing password'});
            }

            const body = {
                username: Helper.firstUpper(value.username),
                email: Helper.lowerCase(value.email),
                password: hash
            }

            User.create(body).then((user) => {
                const token = jwt.sign({data: user}, dbconfig.secret, {
                    expiresIn: 120
                });
                res.cookie('auth', token);
                res.status(httpStatus.CREATED).json({message: 'User created successfully', user, token});
            }).catch((err) => {
                res.status(httpStatus.INTERNAL_SERVER_ERROR).json({message: 'Error occured', user});
            });
        });
    }
}