flag.each_char.map {
    |ch| (ch.ord << 2).to_s(10).to_i.to_s(2).rjust(12,'0').ljust(14, '1')
}.join
