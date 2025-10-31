import { CiCircleAlert } from "react-icons/ci";

export default function Registerinput({label, type, name, register, errors, watch}) {
  return (
        <div className="flex flex-col uppercase font-bold text-white space-y-2">
            <label>{label}</label>
            <input name={name} type={type} className="outline-none p-3 bg-inputbackground text-fontcolor input_rounded" {...register(name)}></input>
            {watch && errors && (
              <p className="flex items-center font-normal text-xs">
                <CiCircleAlert size={20} className="mr-2" />
                {errors}
              </p>
            )}
        </div>
  );
} 
