import { createContext, useEffect, useState } from "react";
import { toast } from 'react-toastify';
import axios from 'axios'; // ✅ Yeh line missing thi

export const AppContent = createContext()

export const AppContextProvider = (props) => {

    //Page refresh karne pe same page pe hi rahega
    axios.defaults.withCredentials = true

    const backendUrl = import.meta.env.VITE_BACKEND_URL
    const [isLoggedin, setIsLoggedin] = useState(false)
    const [userData, setUserData] = useState(false)

    const getAuthState = async ()=>{
        try {
            const {data} = await axios.get(backendUrl + '/api/auth/is-auth')
            if(data.success){
                setIsLoggedin(true)
                getUserData()
            }
        } catch (error) {
              toast.error(error.response?.data?.message || 'Something went wrong')

        }
    }

    const getUserData = async () => {
        try {
            const { data } = await axios.get(backendUrl + '/api/user/data')
              
            data.success ? setUserData(data.userData) : toast.error(data.message)
             
        } catch (error) {
            toast.error(error.response?.data?.message || 'Something went wrong')
        }
    }

    useEffect(() =>{
        getAuthState()
    },[])

    const value = {
        backendUrl,
        isLoggedin,
        setIsLoggedin,
        userData,
        setUserData,
        getUserData
    }

    return (
        <AppContent.Provider value={value}>
            {props.children}
        </AppContent.Provider>
    )
}
