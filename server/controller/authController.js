import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import nodemailer from 'nodemailer';
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from '../config/emailTemplets.js';

const transporter = nodemailer.createTransport({
    host: 'smtp-relay.brevo.com',  // Fixed to Brevo SMTP
    port: 587,
    secure: false,  // false for TLS
    auth: {
        user: process.env.SMTP_USER, // Fixed to use SMTP_USER from .env
        pass: process.env.SMTP_PASS  // Fixed to use SMTP_PASS from .env
    }
});

export const register = async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.json({ success: false, message: "Missing Details" });
    }

    try {
        const existingUser = await userModel.findOne({ email });

        if (existingUser) {
            return res.json({ success: false, message: 'User already exist' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new userModel({ name, email, password: hashedPassword });
        await user.save();

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        // Sending welcome email
        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to New World',
            text: `Welcome to Nikhil Website. Your account has been created with email id: ${email}`
        };

        await transporter.sendMail(mailOption);

        return res.json({ success: true });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
};


export const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.json({ success: false, message: 'Email and Password are required' });
    }

    try {
        
        const user = await userModel.findOne({ email: email.toLowerCase() });

        if (!user) {
            return res.json({ success: false, message: 'Invalid Email' });
        }

        // Compare password with hashed password
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.json({ success: false, message: "Invalid Password" });
        }

        // Generate JWT Token
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        // Set cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        return res.json({ success: true });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};


export const logout = async (req, res)=>{
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        });

        return res.json({success:true, message: "Logged Out"});

    } catch (error) {
        return res.json({success:false, message: error.message})
    }
};

export const sendVerifyOtp = async (req, res) => {
  try {
    const userId = req.userId;

    const user = await userModel.findById(userId);

if (!user) {
  return res.json({ success: false, message: "User not found" });
}

if (user.isAccountVerified) {
  return res.json({ success: false, message: "Account already verified" });
}


    const otp = String(Math.floor(100000 + Math.random() * 900000));

    user.verifyOtp = otp;
    user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000;

    await user.save();

    const mailOption = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: 'Account Verification OTP',
    //   text: `Your OTP is ${otp}. Verify your account using this OTP.`,
      html:EMAIL_VERIFY_TEMPLATE.replace("{{otp}}",otp).replace("{{email}}", user.email)
    };

    await transporter.sendMail(mailOption);

    res.json({ success: true, message: 'Verification OTP sent to email' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

// Check authentication using email
export const verifyEmail = async (req, res) => {
    const { otp } = req.body;
    const userId = req.userId; // ✅ get from middleware

    if (!userId || !otp) {
        return res.json({ success: false, message: "Missing Details" });
    }

    try {
        const user = await userModel.findById(userId);

        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        if (user.verifyOtp === '' || user.verifyOtp !== otp) {
            return res.json({ success: false, message: "Invalid OTP" });
        }

        if (user.verifyOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: "OTP Expired" });
        }

        user.isAccountVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpireAt = 0;

        await user.save();
        return res.json({ success: true, message: "Email Verified successfully" });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

//Check user is Authenticated or not
export const isAuthenticated = async (req, res)=>{
    try {
        return res.json({success: true})
    } catch (error) {
        res.json({ success: false, message: error.message})
    }
};

//Send Password Reset Otp
export const sendResetOtp = async (req,res)=>{
    const{email} = req.body;

    if(!email){
        return res.json({success: false, message: 'Email is Required'})
    };

    try {
        const user = await userModel.findOne({ email });
        if(!user){
            return res.json({success: false, message: 'User not found'})
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 15 * 60 * 10000;

        await user.save();

        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject:'Password Reset OTP',
            // text: `Your OTP for resetting your password is ${otp}. Use this OTP to proceed with resetting your password.`
            html:PASSWORD_RESET_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}",user.email)
        }
         await transporter.sendMail(mailOption)

         return res.json({success: true, message:'OTP sent to your email'})
    } catch (error) {
        res.json({success: false, message: error.message})
    }
};


//Reset password
export const resetPassword = async (req, res)=>{
    const{email, otp, newPassword} = req.body;
     if(!email || !otp || !newPassword){
        return res.json({success: false, message: 'Email, Otp and new Password are required' });    
     };

     try {
        const user = await userModel.findOne({ email });

        if(!user){
            return res.json({success: false, message: 'User not found'})
        }
        
        if(user.resetOtp === '' || user.resetOtp !== otp){
            return res.json({ success: false, message: 'Invalid Otp'})
        };

        if(user.resetOtpExpireAt < Date.now()){
            return res.json({success:false, message: 'OTP Expired'})
        };

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashedPassword;
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;

        await user.save();

        return res.json({success: true, message: 'Password has been reset successfully'})
     } catch (error) {
        res.json({success: false, message: error.message})
     }
}
