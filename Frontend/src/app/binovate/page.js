"use client"

import axios from "axios";
import { useState, useEffect } from "react";
import Nav from "../component/nav";
import { useRouter } from "next/navigation";
import Link from "next/link";

export default function Binovate() {
    const router = useRouter()
    const [data, setData] = useState([])
    const [token, setToken] = useState("")
    const fetchData = async () => {
        try {
            const { data: binData } = await axios.get("https://binovate.onrender.com/api/v1/binovate/status", { headers: { Authorization: `Bearer ${token}` } }
            );
            setData(binData);
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
        <>
            <Nav></Nav>
            <div className="p-2 mt-20">
                <div className="mx-auto max-w-[1800px] flex flex-col p-4 md:p-10 rounded-[20px] border-[2px] border-[#ff9b60] space-y-5 text-binovatefontcolor">
                    <h1 className="uppercase font-bold text-3xl">SCANNED BIN STATUS</h1>
                    <div className="grid sm:grid-cols-1 md:grid-cols-2 xl:grid-cols-3 w-full gap-6">
                        {
                            data.map((item, index) => (
                            <div className="h-[300px] shadow-md rounded-[10px] bg-binovateboxcolor w-full cursor-pointer grid grid-cols-[50%_50%] sm:grid-cols-[40%_60%] items-center justify-center gap-2 p-3" key={index}>
                                <div className="flex flex-col items-center justify-center h-full pl-4 lg:pl-8 max-w-[200px]">
                                    <div className="w-full h-full max-w-[20px] sm:max-w-[20%] max-h-[8px] bg-[#9acfee] rounded-t-[10px]"></div>
                                    <div className="w-full h-full max-w-[120px] sm:max-w-[100%] max-h-[12px] bg-[#9acfee] rounded-[20px]"></div>
                                    <div className="overflow-hidden w-full h-full max-w-[100px] sm:max-w-[88%] max-h-[120px] sm:max-h-[140px] [clip-path:polygon(0%_0%,_100%_0%,_90%_100%,_10%_100%)] bg-[#9acfee] rounded-b-[25px] flex items-end mt-1">
                                        <div className={`flex flex-col h-[${item.status}%] w-full ${item.status >= 80 ? "bg-red-500" : item.status >= 80 ? "bg-orange-500" : item.status >= 50 ? "bg-yellow-500" : "bg-green-500"} items-center justify-end`}>
                                            <h1 className="text-white text-1xl sm:text-2xl md:text-3xl font-bold mb-2">{item.status}%</h1>
                                        </div>
                                    </div>
                                </div>
                                <div className="flex flex-col jutify-center items-center font-medium text-[15px] sm:text-[20px]">
                                    <div className="flex flex-col space-y-3">
                                        <p>Location: {item.location}</p>
                                        <p>BIN ID: {item.bin_id}</p>
                                    </div>
                                </div>
                            </div>
                            ))
                        }
                        <Link href={"/scan"} className="h-[300px] shadow-md rounded-[10px] bg-binovateboxcolor w-full cursor-pointer flex items-center justify-center gap-2 p-3">
                            <h1 className="text-[100px] text-[#9acfee]">+</h1>
                        </Link>
                    </div>
                </div>
            </div>
        </>
    );
}
