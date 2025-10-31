export default function Logininput({label, type, name}) {
  return (
        <div className="flex flex-col uppercase font-bold text-white space-y-2">
            <label>{label}</label>
            <input name={name} type={type} className="outline-none p-3 bg-inputbackground text-fontcolor input_rounded"></input>
        </div>
  );
}
