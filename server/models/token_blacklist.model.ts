import mongoose, { Model, Schema, model } from "mongoose";


interface ITokenBlacklist {
    token:string;
}

const TokenBlacklistSchema: Schema<ITokenBlacklist> = new Schema({
    token:{
        type: String,
        expireAt: Date
    }
}, {timestamps:true})


const TokenBlackListModel: Model<ITokenBlacklist>= model('token_blacklist', TokenBlacklistSchema);

export default TokenBlackListModel;