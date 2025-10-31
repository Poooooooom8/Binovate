"use client"

import axios from "axios";
import { toast } from "react-toastify";
import { useState, useEffect, useRef } from "react";
import Nav from "../component/nav";
import { useRouter } from 'next/navigation'
import { Html5Qrcode } from "html5-qrcode";
import { LuCameraOff } from "react-icons/lu";

export default function Scan() {
    const router = useRouter()
    const [token, setToken] = useState("")
    const [user, setUser] = useState({})
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

    const scanBinId = async (event) => {
        event.preventDefault()
        try {
            const { data } = await axios.post("https://binovate.onrender.com/api/v1/binovate/user/bins", { user_id: user.id, bin_id: event.target.binId.value }, { headers: { Authorization: `Bearer ${token}` } })
            toast.success(data.message)
            router.push("/binovate")

        } catch (error) {
            toast.error(error.response?.data?.detail)
        }
    }

    const qrCodeRegionRef = useRef(null);
    const inputRef = useRef(null);
    const [scanError, setScanError] = useState("")
    useEffect(() => {
        if (!qrCodeRegionRef.current) return;

        const html5QrCode = new Html5Qrcode(qrCodeRegionRef.current.id);
        let isScanning = false;

        Html5Qrcode.getCameras()
            .then(devices => {
                if (devices && devices.length) {
                    isScanning = true;
                    return html5QrCode.start(
                        { facingMode: "environment" },
                        { fps: 10, qrbox: 250 },
                        decodedText => {
                            console.log("decoded:", decodedText);
                            if (inputRef.current) inputRef.current.value = decodedText;
                        },
                        error => {
                            console.warn("Scan error:", error);
                        }
                    );
                } else {
                    setScanError("No camera found on this device.");
                }
            })
            .catch(err => {
                console.error("Camera error:", err);
                setScanError("Cannot access camera. Please allow camera permission or connect a webcam.");
            });

        return () => {
            if (isScanning) {
                html5QrCode
                    .stop()
                    .then(() => html5QrCode.clear())
                    .catch(e => console.warn("Stop error:", e));
            }
        };
    }, []);
    return (
        <>
            <Nav></Nav>
            <div className={`container mx-auto flex flex-col items-center justify-center ${!scanError ? "space-y-20" : "space-y-12"} h-screen`}>
                <h1 className="uppercase font-bold text-5xl">SCAN YOUR BIN!</h1>
                <div className={`flex flex-col items-center ${!scanError ? "space-y-10" : "space-y-3"}`}>
                    <div id="qr-reader" ref={qrCodeRegionRef} style={{ width: "300px", height: "300px", background: "#9acfee", borderRadius: "10%" }} className="flex items-center justify-center cursor-pointer">
                        {
                            scanError ? <LuCameraOff className="w-20 h-20 text-white" />
                                : <></>
                        }
                    </div>
                    <form onSubmit={scanBinId} className="flex space-x-4 p-3">
                        <input name="binId" type="text" ref={inputRef} placeholder="Enter code here" className="w-full px-4 py-2 outline-none border-2 rounded-[10px] border-[#ff7e31] text-fontcolor font-bold bg-inputbackground" />
                        <button type="submit" className="bg-[#ff7e31] px-4 py-2 rounded-[10px] text-white font-bold hover:bg-[#ff6205] cursor-pointer">ADD</button>
                    </form>
                </div>
            </div>
        </>
    );
}
