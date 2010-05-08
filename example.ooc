import mhash/Mhash

m := Mhash new(Algo SHA1)
m feed("Hello")
m feed(" ")
m feed("World!")

"%s sez hi!" format(m hexdigest()) println()
