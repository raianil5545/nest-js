import { Injectable, UnauthorizedException } from "@nestjs/common";
import * as bcrypt from "bcrypt";
import * as jwt from "jsonwebtoken";
import { prisma } from "./db";

@Injectable()
export class AuthService {
    async register(email: string, name: string, password: string) {
        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser){
            throw new UnauthorizedException("User already exists");
        }

        // hash the password
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await prisma.user.create({
            data: {email, name, password: hashedPassword},
            select: {id: true, email:true, name: true}
        })
        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET!, { expiresIn: '7d' });
        return {user, token};
    }
    async signin(email: string, password: string){
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            throw new UnauthorizedException("Invalid credentials");
        }
        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET!, { expiresIn: '7d' });
        return {token, user: {id: user.id, email: user.email, name: user.name}}; 
    }
    async vaidateToken(token: string){
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET!) as {id: string, email: string};
            const user = await prisma.user.findUnique({ where: { id: decoded.id }, select: {id: true, email: true, name: true} });
            if (!user) throw new UnauthorizedException("Invalid token");
            return user;
        } catch (err) {
            throw new UnauthorizedException("Invalid token");
        }
    }
}