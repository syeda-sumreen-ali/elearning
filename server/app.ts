require('dotenv').config();
import express, { Request,Response, NextFunction } from 'express';
export const app = express();
import cors from "cors";
import cookieParser from "cookie-parser";
import ErrorMiddleware from './middleware/error';
import userRouter from './routes/user.route';


//body parser
app.use(express.json({limit:"50mb"}))

//cookie parser
app.use(cookieParser());

// cors => cros origin resource sharing
app.use(
    cors({
        origin:process.env.ORIGIN
    })
)

// Routes
app.use("/api/v1", userRouter)

//testing api
app.get("/test",(req:Request, res:Response, next:NextFunction)=>{
     res.status(200).json({
        success:true,
        message:'API is working'
     })
})

// unknown route
app.all("*", (req:Request, res:Response, next:NextFunction)=>{
    const err = new Error(`Route ${req.originalUrl} not found`) as any;
    res.statusCode= 404;
    next(err)
})

app.use(ErrorMiddleware);