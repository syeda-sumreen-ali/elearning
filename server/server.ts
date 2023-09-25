require("dotenv").config();
import { app } from "./app";


//create server
app.listen(process.env.PORT , ()=>{
    console.log(`Server is connected with port ${process.env.PORT}`)
})