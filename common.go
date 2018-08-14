package wire

func readElements(r io.Reader,elements ...interface{})error{
	for _,element := range elements{
		err := readElement(r,element)
		if err != nil {
			return err
		}
	}
	return nil
}
func readElement(r io.Reader,element interface{})error {
	return binary.Read(r,binary.LittleEndian,element)
}