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
        public static readonly Func<string, (bool success, T value)> tryParseDelegate = CreateTryParseDelegate();
        private static Func<string, (bool, T)> CreateTryParseDelegate()
        {
            var t = typeof(T);
            var mi = t.GetMethod("TryParse", new[] { typeof(string), t.MakeByRefType() });
            if (mi == null) return s => (false, default);
            // Delegate 생성(간단화 예 — 실제로는 DynamicMethod/Expression으로 구현 권장)
            return s =>
            {
                object[] args = new object[] { s, null };
                bool ok = (bool)mi.Invoke(null, args); // 한 번만 발생; 호출 빈도는 델리게이트로 대체
                return (ok, ok ? (T)args[1] : default);
            };
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
                    var (success, val) = tryParseDelegate.Invoke(DecryptValue);
                    return success ? val : default;
                }
                catch
                {
                    return default;    
                }
                
            }
            set
            {
                secureKey = Crypto.MakeSecureKey();
                secureValue = Crypto.Encrypt(value.ToString(), secureKey);
            }
        }
    }

}
