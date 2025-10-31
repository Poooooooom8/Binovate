"use client"

import Link from "next/link";
import Logininput from "../component/logininput";
import { toast } from "react-toastify";
import axios from "axios";
import { useRouter } from 'next/navigation'
import Themetoggle from "../component/themetoggle";

export default function Login() {
    const router = useRouter()
    const handleSubmit = async (event) => {
        event.preventDefault()
        try {
            const { data } = await axios.post("https://binovate.onrender.com/api/login", {
                username: event.target.username.value,
                password: event.target.password.value
            })
            const token = data.access_token
            document.cookie = `access_token=${token}; path=/; max-age=86400; secure; samesite=strict`;
            toast.success(data.message)
            router.push('/binovate')
        } catch (error) {
            toast.error(error.response?.data?.detail)
        }
    }
    return (
        <>
            <div className="relative mx-auto h-screen flex items-center justify-center bg-[url(/itbackground.jpg)] bg-black/25 bg-blend-multiply bg-cover">
                <div className="overflow-hidden max-w-[500px] py-30 w-full bg-loginbackground dark: flex flex-col items-center justify-center space-y-3 drop-shadow-lg drop-shadow-[background]/50">
                    <form onSubmit={handleSubmit} className="flex flex-col items-center">
                        <div className="absolute p-25 bg-boxcolor z-100 left-[-125px] top-[-125px] rotate-40 border-[5px] border-white"></div>
                        <div className="space-y-6">
                            <Logininput label="username :" type="text" name="username"/>
                            <Logininput label="password :" type="password" name="password"/>
                            <Link href="/register" className="text-white font-medium hover:underline">Don't have any account.</Link>
                        </div>
                        <button className="px-10 py-4 mt-5 uppercase cursor-pointer bg-buttoncolor border-[2px] border-white font-bold text-white hover:bg-white hover:text-loginbackground">Login</button>
                    </form>
                    <Themetoggle classname="absolute bottom-4 right-4"></Themetoggle>
                </div>
            </div>
        </>
    );
}
