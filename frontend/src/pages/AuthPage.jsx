import React, { useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Mail, Lock, User, Loader2 } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { InputOTP, InputOTPGroup, InputOTPSlot, InputOTPSeparator } from "@/components/ui/input-otp";
import { useAuthStore } from "@/store/authStore";

export default function AuthPage() {
  const { login, register, verifyMfa, isLoading, error } = useAuthStore();
  
  // Local state
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [mfaOpen, setMfaOpen] = useState(false);
  const [tempToken, setTempToken] = useState(null);
  const [otp, setOtp] = useState("");

  const handleLogin = async (e) => {
    e.preventDefault();
    const res = await login(email, password);
    if (res?.requiresMfa) {
      setTempToken(res.tempToken);
      setMfaOpen(true);
    } else if (res?.success) {
      window.location.href = "/dashboard";
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    const res = await register(name, email, password);
    if (res?.success) {
      window.location.href = "/dashboard";
    }
  };

  const handleMfaSubmit = async (e) => {
    e.preventDefault();
    const res = await verifyMfa(otp, tempToken);
    if (res?.success) {
      setMfaOpen(false);
      window.location.href = "/dashboard";
    }
  };

  const handleOAuth = (provider) => {
    window.location.href = `${import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000'}/api/auth/${provider}`;
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-zinc-950 p-4 bg-[url('https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?q=80&w=2564&auto=format&fit=crop')] bg-cover bg-center">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-[2px]"></div>
      
      <div className="z-10 w-full max-w-md animate-in fade-in zoom-in duration-500">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-extrabold tracking-tight text-white mb-2">V.ME Auth</h1>
          <p className="text-zinc-400">Secure. Fast. Reliable.</p>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-red-500/20 border border-red-500/50 rounded-md text-red-200 text-sm text-center">
            {error}
          </div>
        )}

        <Tabs defaultValue="login" className="w-full">
          <TabsList className="grid w-full grid-cols-2 mb-6 bg-zinc-900/80 border border-zinc-800 backdrop-blur-md">
            <TabsTrigger value="login" className="data-[state=active]:bg-zinc-800">Login</TabsTrigger>
            <TabsTrigger value="register" className="data-[state=active]:bg-zinc-800">Register</TabsTrigger>
          </TabsList>
          
          <TabsContent value="login">
            <Card className="bg-zinc-900/80 border-zinc-800 text-white backdrop-blur-xl shadow-2xl">
              <CardHeader>
                <CardTitle>Welcome back</CardTitle>
                <CardDescription className="text-zinc-400">Enter your credentials to access your account.</CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleLogin} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="email">Email</Label>
                    <div className="relative">
                      <Mail className="absolute left-3 top-2.5 h-5 w-5 text-zinc-500" />
                      <Input id="email" type="email" placeholder="m@example.com" value={email} onChange={(e)=>setEmail(e.target.value)} required className="pl-10 bg-zinc-950/50 border-zinc-800 focus-visible:ring-emerald-500" />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="password">Password</Label>
                      <a href="#" className="text-sm text-emerald-500 hover:underline">Forgot password?</a>
                    </div>
                    <div className="relative">
                      <Lock className="absolute left-3 top-2.5 h-5 w-5 text-zinc-500" />
                      <Input id="password" type="password" value={password} onChange={(e)=>setPassword(e.target.value)} required className="pl-10 bg-zinc-950/50 border-zinc-800 focus-visible:ring-emerald-500" />
                    </div>
                  </div>
                  <Button type="submit" disabled={isLoading} className="w-full bg-emerald-600 hover:bg-emerald-700 text-white">
                    {isLoading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null} Login
                  </Button>
                </form>
                
                <div className="relative my-6">
                  <div className="absolute inset-0 flex items-center">
                    <span className="w-full border-t border-zinc-800" />
                  </div>
                  <div className="relative flex justify-center text-xs uppercase">
                    <span className="bg-zinc-900 px-2 text-zinc-500">Or continue with</span>
                  </div>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <Button variant="outline" type="button" onClick={() => handleOAuth('github')} className="border-zinc-800 bg-zinc-950/50 hover:bg-zinc-800 text-white">
                    <svg className="mr-2 h-4 w-4" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg> Github
                  </Button>
                  <Button variant="outline" type="button" onClick={() => handleOAuth('google')} className="border-zinc-800 bg-zinc-950/50 hover:bg-zinc-800 text-white">
                    <svg className="mr-2 h-4 w-4" viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>
                    Google
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="register">
            <Card className="bg-zinc-900/80 border-zinc-800 text-white backdrop-blur-xl shadow-2xl">
              <CardHeader>
                <CardTitle>Create an account</CardTitle>
                <CardDescription className="text-zinc-400">Enter your details below to create your account.</CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleRegister} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="name">Full Name</Label>
                    <div className="relative">
                      <User className="absolute left-3 top-2.5 h-5 w-5 text-zinc-500" />
                      <Input id="name" placeholder="John Doe" value={name} onChange={(e)=>setName(e.target.value)} required className="pl-10 bg-zinc-950/50 border-zinc-800 focus-visible:ring-emerald-500" />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="email-reg">Email</Label>
                    <div className="relative">
                      <Mail className="absolute left-3 top-2.5 h-5 w-5 text-zinc-500" />
                      <Input id="email-reg" type="email" placeholder="m@example.com" value={email} onChange={(e)=>setEmail(e.target.value)} required className="pl-10 bg-zinc-950/50 border-zinc-800 focus-visible:ring-emerald-500" />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="password-reg">Password</Label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-2.5 h-5 w-5 text-zinc-500" />
                      <Input id="password-reg" type="password" value={password} onChange={(e)=>setPassword(e.target.value)} required className="pl-10 bg-zinc-950/50 border-zinc-800 focus-visible:ring-emerald-500" />
                    </div>
                  </div>
                  <Button type="submit" disabled={isLoading} className="w-full bg-emerald-600 hover:bg-emerald-700 text-white mt-4">
                    {isLoading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null} Create Account
                  </Button>
                </form>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* MFA Dialog */}
        <Dialog open={mfaOpen} onOpenChange={setMfaOpen}>
          <DialogContent className="bg-zinc-900 border-zinc-800 text-white sm:max-w-md">
            <DialogHeader>
              <DialogTitle className="text-xl">Two-Factor Authentication</DialogTitle>
              <DialogDescription className="text-zinc-400">
                Please enter the 6-digit code from your authenticator app.
              </DialogDescription>
            </DialogHeader>
            <form onSubmit={handleMfaSubmit} className="space-y-6 pt-4">
              <div className="flex justify-center">
                <InputOTP maxLength={6} value={otp} onChange={setOtp}>
                  <InputOTPGroup>
                    <InputOTPSlot index={0} className="w-12 h-14 text-lg bg-zinc-950 border-zinc-700" />
                    <InputOTPSlot index={1} className="w-12 h-14 text-lg bg-zinc-950 border-zinc-700" />
                    <InputOTPSlot index={2} className="w-12 h-14 text-lg bg-zinc-950 border-zinc-700" />
                  </InputOTPGroup>
                  <InputOTPSeparator />
                  <InputOTPGroup>
                    <InputOTPSlot index={3} className="w-12 h-14 text-lg bg-zinc-950 border-zinc-700" />
                    <InputOTPSlot index={4} className="w-12 h-14 text-lg bg-zinc-950 border-zinc-700" />
                    <InputOTPSlot index={5} className="w-12 h-14 text-lg bg-zinc-950 border-zinc-700" />
                  </InputOTPGroup>
                </InputOTP>
              </div>
              <Button type="submit" disabled={isLoading || otp.length !== 6} className="w-full bg-emerald-600 hover:bg-emerald-700 text-white">
                {isLoading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null} Verify Code
              </Button>
            </form>
          </DialogContent>
        </Dialog>
      </div>
    </div>
  );
}
