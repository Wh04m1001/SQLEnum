using System.Data.SqlClient;
using System.DirectoryServices;
using System;
using System.Collections.Generic;

namespace SQLEnum
{
    public class Program
    {
        static void Main(string[] args)
        {

            Run();
        }
        public static void Run()
        {
            HashSet<string> hosts = Program.EnumSQLServers();
            foreach (string sqlserver in hosts)
            {
                Program.SqlConn(sqlserver);
            }

        }
        public static HashSet<string> EnumSQLServers()
        {
            
            try
            {
                //Enumerate SQL servers by scanning SPN's 
                HashSet<string> spn = new HashSet<string>();
                DirectoryEntry ldap = new DirectoryEntry();
                DirectorySearcher query = new DirectorySearcher(ldap)
                {
                    Filter = ("(&(objectclass=person)(serviceprincipalname=*mssql*))")
                };
                foreach (SearchResult res in query.FindAll())
                {

                    foreach (string spns in res.Properties["serviceprincipalname"])
                    {
                        spn.Add(spns.Split('/')[1].Split(':')[0]);
                    }
                    Int32 count = spn.Count;

                    if (count != 0)
                    {
                        Console.WriteLine("Found {0} SQL Servers!", count);
                        return spn;
                    }
                    else
                    {
                        Console.WriteLine("Found 0 SQL Servers. Exiting!");
                        Environment.Exit(0);
                    }
                }
            }
            catch 
            {
                Console.WriteLine($"Can't reach domain!");
                Environment.Exit(0);
            }
            return new HashSet<string>();
        }

        public static void CurrentUser(SqlConnection con)
        {
            string query = "Select system_user;";
            SqlCommand command = new SqlCommand(query, con);

            SqlDataReader result = command.ExecuteReader();

            result.Read();
            Console.WriteLine("Current user: {0}", result[0].ToString());
            result.Close();
        }
        public static void EnumDB(SqlConnection con)
        {
            string query;
            SqlCommand command;
            SqlDataReader result;
            query = "SELECT name FROM master..sysdatabases;";
            command = new SqlCommand(query, con);
            result = command.ExecuteReader();
            var db = new List<string>();
            while (result.Read() == true)
            {

                db.Add(result[0].ToString());

            }
            result.Close();
            string dbs = string.Join(",", db);
            Console.WriteLine($"Available  Database's: {dbs}", dbs);
        }

        public static void RoleEnum(SqlConnection con)
        {
            string[] roles = { "public", "sysadmin", "serveradmin", "securityadmin", "processadmin", "setupadmin", "bulkadmin", "diskadmin", "dbcreator" };
            string query;
            SqlCommand command;
            SqlDataReader result;
            Int32 is_member;
            var role_list = new List<string>();

            foreach (string role in roles)

            {

                query = string.Format("SELECT IS_SRVROLEMEMBER('{0}');", role);
                command = new SqlCommand(query, con);
                result = command.ExecuteReader();
                result.Read();
                is_member = Int32.Parse(result[0].ToString());
                result.Close();
                if (is_member == 1)
                {
                    role_list.Add(role);

                }


            }
            string membership = string.Join(",", role_list);
            Console.WriteLine($"User role membership: {membership}", membership);

        }
        public static void EnumImpersonation(SqlConnection con)

        {
            string query;
            SqlCommand command;
            SqlDataReader result;
            query = "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';";
            command = new SqlCommand(query, con);
            result = command.ExecuteReader();
            
            var impersonate = new List<string>();
            while (result.Read() == true)
            {
                impersonate.Add(result[0].ToString());
            }
            if (impersonate.Count != 0)
            {
                string login = string.Join(",", impersonate);
                Console.WriteLine($"Logins that can be impersonated: {login}", login);
            }
            else
            {
                Console.WriteLine("User dont have impersonate prvileges!");
            }
            result.Close();
        }
        public static void EnumTrustworthyDB(SqlConnection con)
        {
            string query;
            SqlCommand command;
            SqlDataReader result;
            query = "SELECT a.name FROM master..sysdatabases as a INNER JOIN sys.databases as b ON a.name=b.name where b.is_trustworthy_on='1';";
            command = new SqlCommand(query, con);
            result = command.ExecuteReader();
            var trustdb = new List<string>();
            while (result.Read() == true)
            {

                trustdb.Add(result[0].ToString());

            }
            result.Close();
            string trustworthydb = string.Join(",", trustdb);
            Console.WriteLine($"Trustworthy Database's: {trustworthydb}", trustworthydb);
        }
        public static void LinkedServers(SqlConnection con)
        {
            string query;
            SqlCommand command;
            SqlDataReader result;
            query = "Select srvname,providername,dataaccess from master..sysservers where isremote='0'";
            command = new SqlCommand(query, con);
            result = command.ExecuteReader();
            var linkedservers = new List<string>();
            while (result.Read() == true)
            {

                linkedservers.Add(result[0].ToString());

            }
            string sqlservers = string.Join(",", linkedservers);
            Console.WriteLine($"Linked SQL Server's: {sqlservers}", sqlservers);
        }
        public static void SqlConn(string sqlserver)
        {

            string db = "master";
            string connstring = "Server = " + sqlserver + "; Database = " + db + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(connstring);
            Console.WriteLine($"Authenticating to SQL server: {sqlserver}", sqlserver);
            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            CurrentUser(con);
            RoleEnum(con);
            EnumDB(con);
            EnumImpersonation(con);
            EnumTrustworthyDB(con);
            LinkedServers(con);
            con.Close();

        }
    }
    //Applocker Bypass
    //Usage: InstallUtil.exe  /logfile= /logtoconsole=false /U <pathtofile>
    [System.ComponentModel.RunInstaller(true)]
    public class Bypass : System.Configuration.Install.Installer
    {

        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            base.Uninstall(savedState);

            Program.Run();
        }
    }
}
