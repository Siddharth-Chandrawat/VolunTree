import express from "express";
import { login } from "../controllers/auth.js";
import User from "../models/User.js";
import bcrypt from "bcrypt";
import nodemailer from "nodemailer";
import jwt from "jsonwebtoken";
import { forgot } from "../controllers/auth.js";
import { reset } from "../controllers/auth.js"


const router = express.Router();

router.post("/login", login);

router.post("/forgot", forgot);


router.post("/reset/:token", reset);

export default router;
