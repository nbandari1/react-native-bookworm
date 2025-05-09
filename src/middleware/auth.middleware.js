import jwt from "jsonwebtoken";
import User from "../models/User.js";



const protectRoute = async(req, res, next) => {
    try {
        //get token
        const token = req.header("Authorization").replace("Bearer ", "");
        if (!token) return res.status(401).json({message: "No authentication token, access denied"});

        //verification
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        //finding user
        const user = await User.findById(decoded.UserId).select("-password");

        if (!user) return res.status(401).json({message: "Token is not valid"});

        req.user = user;
        next();
    } catch (error) {
        console.error("Authorization error:", error.message);
        res.status(401).json({message: "Token is not valid"});
    }
};

export default protectRoute;