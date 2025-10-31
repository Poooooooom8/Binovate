"use client"

import Link from "next/link";
import Registerinput from "../component/registerinput";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod"
import { useForm } from "react-hook-form";
import axios from "axios";
import zxcvbn from "zxcvbn";
import { useState, useEffect } from "react";
import { toast } from "react-toastify";
import { useRouter } from 'next/navigation'
import Themetoggle from "../component/themetoggle";


const FormSchema = z.object({
  username: z.string().min(2, "Username must be at least 2 charaters long.").max(32, "Username must be no more than 32 characters long.").regex(/^[a-zA-Z0-9]+$/, "Only letters and numbers are allowed."),
  password: z.string().min(6, "Password must be at least 6 characters long.").max(32, "Password must be more than 32 characters long."),
  confirm_password: z.string().min(6, "Password must be at least 6 characters long.").max(32, "Password must be more than 32 characters long.")
}).refine((data) => data.password === data.confirm_password, { message: "Password do not match.", path: ["confirm_password"] })

export default function Register() {
  const router = useRouter()
  const { register, handleSubmit, watch, reset, formState: { errors, isSubmitting } } = useForm({ resolver: zodResolver(FormSchema) })
  const onSubmit = async (values) => {
    try {
      const { data } = await axios.post("https://binovate.onrender.com/api/register", {
        ...values
      })
      reset()
      toast.success(data.message)
      router.push("/login")
    } catch (error) {
      toast.error(error.response.data.detail)
    }
  }
  const validatePassword = () => {
    let password = watch().password
    return zxcvbn(password ? password : "").score
  }
  const [passwordScore, setPasswordScore] = useState(0)
  useEffect(() => {
    setPasswordScore(validatePassword())
  }, [watch().password])
  return (
    <>
      <div className="relative mx-auto h-screen flex items-center justify-center bg-[url(/itbackground.jpg)] bg-black/25 bg-blend-multiply bg-cover">
        <div className="overflow-hidden max-w-[500px] py-30 w-full bg-loginbackground flex flex-col items-center justify-center space-y-3 drop-shadow-lg drop-shadow-background/50">
          <form onSubmit={handleSubmit(onSubmit)} className="flex flex-col items-center">
            <div className="absolute p-25 bg-boxcolor z-100 left-[-125px] top-[-125px] rotate-40 border-[5px] border-white"></div>
            <div className="space-y-6">
              <Registerinput label="username :" type="text" name="username" register={register} errors={errors?.username?.message} watch={watch("username")} />
              <div className="relative">
                <Registerinput label="password :" type="password" name="password" register={register} errors={errors?.password?.message} watch={watch("password")} />
                {
                  watch().password?.length
                    ? passwordScore >= 4
                      ? <p className="absolute text-green-500 font-medium text-sm top-[2px] right-0 uppercase text-xs">strong</p>
                      : passwordScore >= 3
                        ? <p className="absolute text-yellow-500 font-medium text-sm top-[2px] right-0 uppercase text-xs">moderate</p>
                        : passwordScore >= 2
                          ? <p className="absolute text-orange-500 font-medium text-sm top-[2px] right-0 uppercase text-xs">weak</p>
                          : <p className="absolute text-red-500 font-medium text-sm top-[2px] right-0 uppercase text-xs">too weak</p>
                    : <></>
                }
              </div>
              <Registerinput label="confirm password :" type="password" name="confirm_password" register={register} errors={errors?.confirm_password?.message} watch={watch("confirm_password")} />
              <Link href="/login" className="text-white font-medium hover:underline">Already have an account.</Link>
            </div>
            <button className="px-10 py-4 mt-5 uppercase cursor-pointer bg-buttoncolor border-[2px] border-white font-bold text-white hover:bg-white hover:text-loginbackground">Register</button>
          </form>
          <Themetoggle classname="absolute bottom-4 right-4"></Themetoggle>
        </div>
      </div>
    </>
  );
}
