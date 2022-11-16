using System;
using System.Reflection;


namespace beio.Security
{
    public class Variable<T>
    {
        #region Private Member
        private string secureKey;
        private string secureValue = string.Empty;
        private Type[] getMethodTypes;
        private Type tType;
        private MethodInfo method;

        #endregion
        #region Static Method
        #region Variable Type Cast
        public static implicit operator Variable<T>(T a)
        {
            return new Variable<T>(a);
        }
        public static implicit operator T(Variable<T> a)
        {
            if (a == null)
                a = new Variable<T>();
            return a.value;
        }
        public override string ToString()
        {
            return value.ToString();
        }
        #endregion
        #endregion
        #region Constructor
        public Variable()
        {
            tType = typeof(T);
            getMethodTypes = new Type[] { typeof(string), typeof(T).MakeByRefType() };
            method = tType.GetMethod("TryParse", getMethodTypes);
        }
        public Variable(T value) : this()
        {
            secureKey = Crypto.MakeSecureKey();
            secureValue = Crypto.Encrypt(value.ToString(), secureKey);
        }
        #endregion
        public T value
        {
            get
            {
                // 암호화 해제한 값
                object DecryptValue = null;
                try
                {
                    DecryptValue = Crypto.Decrypt(secureValue, secureKey);
                }
                catch
                {
                }
                if (DecryptValue == null)
                    return default;
                // Numberic에 대한 함수 여부를 체크한다.
                if (method == null)
                    return (T)DecryptValue;
                // TryParse 함수를 호출 TryParse 에 대한 처리를 시작한다.
                object[] parameters = new object[] { DecryptValue, null };
                bool result = (bool)method.Invoke(null, parameters);
                if (result) return (T)parameters[1];
                return default;
            }
            set
            {
                secureKey = Crypto.MakeSecureKey();
                secureValue = Crypto.Encrypt(value.ToString(), secureKey);
            }
        }
    }

}