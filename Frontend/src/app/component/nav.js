import { useRouter } from 'next/navigation'
import { MdLogout } from "react-icons/md";
import axios from "axios";
import { useState, useEffect } from "react";
import Themetoggle from './themetoggle';

export default function Nav() {
    const router = useRouter()
    const handleLogout = () => {
        document.cookie = "access_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
        router.push("/login")
    }
    const [user, setUser] = useState({})
    const [token, setToken] = useState("")
    const fetchData = async () => {
        try {
            const { data: user } = await axios.get("https://binovate.onrender.com/api/users/me", { headers: { Authorization: `Bearer ${token}` } }
            );
            setUser(user);
        } catch (err) {
            router.push("/login")
        }
    };
    useEffect(() => {
        const getTokenFromCookie = () => {
            const cookies = document.cookie.split("; ");
            const tokenCookie = cookies.find(row => row.startsWith("access_token="));
            if (!tokenCookie) {
                return "access_token=NOCOOKIE";
            }
            return tokenCookie.split("=")[1];
        }
        const tokenValue = getTokenFromCookie()
        setToken(tokenValue)
        if (token) {
            fetchData()
        }
    }, [token])
    return (
        <div className="w-full h-[50px] px-4 bg-navbackground fixed top-0 text-white flex justify-between items-center z-100">
            <h1 className="font-bold cursor-pointer" onClick={() => router.push("/binovate")}>BINOVATE</h1>
            <div className="flex space-x-5 items-center">
                <p className="font-bold">{user.username}</p>
                <MdLogout onClick={handleLogout} className="w-[22px] h-[22px] cursor-pointer" />
                <Themetoggle></Themetoggle>
            </div>
        </div>
    );
}
