require("dotenv").config();
import { Request, Response, NextFunction} from "express";
import userModel, { IUser } from "../models/user.model";
import ErrorHandler from "../utils/ErrorHandler";
import { CatchAsyncError } from "../middleware/catchAsyncErrors";
import jwt, { Secret } from "jsonwebtoken";
import ejs from "ejs";
import path from "path";
import sendMail from "../utils/sendMail";
import TokenBlackListModel from "../models/token_blacklist.model";

// Register user
interface IRegistrationBody {
  name: string;
  email: string;
  password: string;
  avatar?: string;
}

export const registrationUser = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { name, email, password } = req.body;

      const isEmailExist = await userModel.findOne({ email });
      if (isEmailExist) {
        return next(new ErrorHandler("Email already exist", 400));
      }

      const user: IRegistrationBody = {
        name,
        email,
        password,
      };

      const activationToken = createActivationToken(user);

      const activationCode = activationToken.activationCode;

      const newUser = new userModel({
        name:user.name,
        avatar:user.avatar,
        email:user.email,
        password:user.password,
        activationToken
      })

      await newUser.save();
      
      const data = {
        user: { name: user.name },
        activationCode
      };
      const html = await ejs.renderFile(
        path.join(__dirname, "../mails/activation-mail.ejs"),
        data
      );

      try {
        await sendMail({
          email: user.email,
          subject: "Activate your account",
          template: "activation-mail.ejs",
          data,
        });

        res.status(201).json({
          success: true,
          message: `Please check you email: ${user.email} to activate your account`,
          activationToken: activationToken.token,
        });
      } catch (error: any) {
        return next(new ErrorHandler(error.message, 400));
      }
    } catch (error: any) {
      return next(new ErrorHandler(error.message, 400));
    }
  }
);

interface IActivationToken {
  token: string;
  activationCode: string;
}

export const createActivationToken = (
  user: Partial<IRegistrationBody>
): IActivationToken => {
  const activationCode = Math.floor(1000 + Math.random() * 9000).toString();

  const token = jwt.sign(
    { user, activationCode },
    process.env.ACTIVATION_SECRET as Secret,
    { expiresIn: "5m" }
  );
  return { token, activationCode };
};

interface IActivationRequest{
  activation_token:string;
  activation_code:string;
}

export const activateUser = CatchAsyncError(async(req:Request, res:Response, next:NextFunction)=>{
  try {
    const {activation_token, activation_code}= req.body as IActivationRequest;
    
    const isBlacklistToken= await TokenBlackListModel.find({token:activation_token});

    if(isBlacklistToken){
      console.log(isBlacklistToken);
      return next(new ErrorHandler("jwt expired", 400))
    }

    const newUser:{ user: IUser, activationCode:string } = jwt.verify(
       activation_token,
       process.env.ACTIVATION_SECRET as Secret
       ) as { user:IUser, activationCode:string}
 
       if(newUser.activationCode !== activation_code){
          return next(new ErrorHandler("Invalid activation code", 400))
       }

       const {name, email, password}= newUser.user;
       
       const userDetails = await userModel.findOne({email})
       
       if(!userDetails){
        return next(new ErrorHandler("User not found", 400))
       }

      let updatedUser= await userModel.findByIdAndUpdate(userDetails._id,{isVerified:true}, {new:true})
      
      //blacklist token
      const blacklist = new TokenBlackListModel({
        token:activation_token,
        expireAt: new Date().setHours(new Date().getHours()+1) // date after one hr
      }) 

      await blacklist.save()
       res.json({
        success:true,
        message:'Account activated successfully',
        data:updatedUser
      })


      } catch (error:any) {
    next(new ErrorHandler(error.message, 400))
  }
})