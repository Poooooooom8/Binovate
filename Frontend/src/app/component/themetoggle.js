import { useTheme } from "next-themes";
import { FaRegMoon } from "react-icons/fa";
import { FaRegSun } from "react-icons/fa";

export default function Themetoggle({ classname }) {
    const { theme, setTheme } = useTheme()
    const handleTheme = () => {
        setTheme(theme === "light" ? "dark" : "light")
    }
    return (
        <>
            <div className={`${classname}`}>
                <button onClick={handleTheme} className="flex self-end cursor-pointer text-white">{ 
                theme === "light" ? <FaRegMoon />
                                  : <FaRegSun></FaRegSun>
            }</button>
            </div>
        </>
    );
} 
