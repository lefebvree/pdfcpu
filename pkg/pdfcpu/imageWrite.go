/*
Copyright 2018 The pdfcpu Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package pdfcpu

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"

	"github.com/hhrutter/tiff"
	"github.com/pdfcpu/pdfcpu/pkg/filter"
	"github.com/pdfcpu/pdfcpu/pkg/log"
	"github.com/pkg/errors"
)

const (
	pngExt  = ".png"
	tiffExt = ".tiff"
	jpgExt  = ".jpg"
	jpxExt  = ".jpx"
)

// Errors to be identified.
var (
	ErrUnsupportedColorSpace   = errors.New("unsupported color space")
	ErrUnsupported16BPC        = errors.New("unsupported 16 bits per component")
	ErrUnsupportedTIFFCreation = errors.New("unsupported tiff file creation")
)

// colValRange defines a numeric range for color space component values that may be inverted.
type colValRange struct {
	min, max float64
	inv      bool
}

// PDFImage represents a XObject of subtype image.
type PDFImage struct {
	objNr    int
	sd       *StreamDict
	bpc      int
	w, h     int
	softMask []byte
	decode   []colValRange
}

func decodeArr(a Array) []colValRange {

	if a == nil {
		//println("decodearr == nil")
		return nil
	}

	var decode []colValRange
	var min, max, f64 float64

	for i, f := range a {
		switch o := f.(type) {
		case Integer:
			f64 = float64(o.Value())
		case Float:
			f64 = o.Value()
		}
		if i%2 == 0 {
			min = f64
			continue
		}
		max = f64
		var inv bool
		if min > max {
			min, max = max, min
			inv = true
		}
		decode = append(decode, colValRange{min: min, max: max, inv: inv})
	}

	return decode
}

func pdfImage(xRefTable *XRefTable, sd *StreamDict, objNr int) (*PDFImage, error) {

	bpc := *sd.IntEntry("BitsPerComponent")
	//if bpc == 16 {
	//	return nil, ErrUnsupported16BPC
	//}

	w := *sd.IntEntry("Width")
	h := *sd.IntEntry("Height")

	decode := decodeArr(sd.ArrayEntry("Decode"))
	//fmt.Printf("decode: %v\n", decode)

	sm, err := softMask(xRefTable, sd, w, h, objNr)
	if err != nil {
		return nil, err
	}

	return &PDFImage{
		objNr:    objNr,
		sd:       sd,
		bpc:      bpc,
		w:        w,
		h:        h,
		softMask: sm,
		decode:   decode,
	}, nil
}

// Identify the color lookup table for an Indexed color space.
func colorLookupTable(xRefTable *XRefTable, o Object) ([]byte, error) {

	var lookup []byte
	var err error

	o, _ = xRefTable.Dereference(o)

	switch o := o.(type) {

	case StringLiteral:
		return Unescape(string(o))

	case HexLiteral:
		lookup, err = o.Bytes()
		if err != nil {
			return nil, err
		}

	case StreamDict:
		lookup, err = streamBytes(&o)
		if err != nil || lookup == nil {
			return nil, err
		}
	}

	return lookup, nil
}

func decodePixelColorValue(p uint8, bpc, c int, decode []colValRange) uint8 {

	// p ...the color value for this pixel
	// c ...applicable index of a color component in the decode array for this pixel.

	if decode == nil {
		decode = []colValRange{{min: 0, max: 255}}
	}

	min := decode[c].min
	max := decode[c].max

	q := 1
	for i := 1; i < bpc; i++ {
		q = 2*q + 1
	}

	v := uint8(min + (float64(p) * (max - min) / float64(q)))

	if decode[c].inv {
		v = v ^ 0xff
	}

	return v
}

func streamBytes(sd *StreamDict) ([]byte, error) {

	fpl := sd.FilterPipeline
	if fpl == nil {
		log.Info.Printf("streamBytes: no filter pipeline\n")
		err := decodeStream(sd)
		if err != nil {
			return nil, err
		}
		return sd.Content, nil
	}

	// Ignore filter chains with length > 1
	if len(fpl) > 1 {
		log.Info.Printf("streamBytes: more than 1 filter\n")
		return nil, nil
	}

	switch fpl[0].Name {

	case filter.Flate:
		err := decodeStream(sd)
		if err != nil {
			return nil, err
		}

	default:
		log.Debug.Printf("streamBytes: filter not \"Flate\": %s\n", fpl[0].Name)
		return nil, nil
	}

	return sd.Content, nil
}

// Return the soft mask for this image or nil.
func softMask(xRefTable *XRefTable, d *StreamDict, w, h, objNr int) ([]byte, error) {

	// TODO Process optional "Matte".

	o, _ := d.Find("SMask")
	if o == nil {
		// No soft mask available.
		return nil, nil
	}

	// Soft mask present.

	sd, err := xRefTable.DereferenceStreamDict(o)
	if err != nil {
		return nil, err
	}

	sm, err := streamBytes(sd)
	if err != nil {
		return nil, err
	}

	bpc := sd.IntEntry("BitsPerComponent")
	if bpc == nil {
		log.Info.Printf("softMask: obj#%d - ignoring soft mask without bpc\n%s\n", objNr, sd)
		return nil, nil
	}

	// TODO support soft masks with bpc != 8
	// Will need to return the softmask bpc to caller.
	if *bpc != 8 {
		log.Info.Printf("softMask: obj#%d - ignoring soft mask with bpc=%d\n", objNr, *bpc)
		return nil, nil
	}

	if sm != nil {
		if len(sm) != (*bpc*w*h+7)/8 {
			log.Info.Printf("softMask: obj#%d - ignoring corrupt softmask\n%s\n", objNr, sd)
			return nil, nil
		}
	}

	return sm, nil
}

func tiffImgBuffer(img *image.CMYK) (*bytes.Buffer, error) {
	// TODO softmask handling.
	var buf bytes.Buffer
	err := tiff.Encode(&buf, img, nil)
	return &buf, err
}

func tiffDeviceCMYKBuffer(im *PDFImage) (*bytes.Buffer, error) {

	b := im.sd.Content

	log.Debug.Printf("writeDeviceCMYKToTIFF: CMYK objNr=%d w=%d h=%d bpc=%d buflen=%d\n", im.objNr, im.w, im.h, im.bpc, len(b))

	img := image.NewCMYK(image.Rect(0, 0, im.w, im.h))

	i := 0

	// TODO support bpc, decode and softMask.

	for y := 0; y < im.h; y++ {
		for x := 0; x < im.w; x++ {
			img.Set(x, y, color.CMYK{C: b[i], M: b[i+1], Y: b[i+2], K: b[i+3]})
			i += 4
		}
	}

	return tiffImgBuffer(img)
}

func pngImgBuffer(img image.Image) (*bytes.Buffer, error) {
	var buf bytes.Buffer
	err := png.Encode(&buf, img)
	return &buf, err
}

func pngDeviceGrayBuffer(im *PDFImage) (*bytes.Buffer, error) {

	b := im.sd.Content

	log.Debug.Printf("writeDeviceGrayToPNG: objNr=%d w=%d h=%d bpc=%d buflen=%d\n", im.objNr, im.w, im.h, im.bpc, len(b))

	// Validate buflen.
	// For streams not using compression there is a trailing 0x0A in addition to the imagebytes.
	if len(b) < (im.bpc*im.w*im.h+7)/8 {
		return nil, errors.Errorf("writeDeviceGrayToPNG: objNr=%d corrupt image object %v\n", im.objNr, *im.sd)
	}

	img := image.NewGray(image.Rect(0, 0, im.w, im.h))

	// TODO support softmask.
	i := 0
	for y := 0; y < im.h; y++ {
		for x := 0; x < im.w; {
			p := b[i]
			for j := 0; j < 8/im.bpc; j++ {
				pix := p >> (8 - uint8(im.bpc))
				v := decodePixelColorValue(pix, im.bpc, 0, im.decode)
				//fmt.Printf("x=%d y=%d pix=#%02x v=#%02x\n", x, y, pix, v)
				img.Set(x, y, color.Gray{Y: v})
				p <<= uint8(im.bpc)
				x++
			}
			i++
		}
	}

	return pngImgBuffer(img)
}

func pngDeviceRGBBuffer(im *PDFImage) (*bytes.Buffer, error) {

	b := im.sd.Content

	log.Debug.Printf("writeDeviceRGBToPNG: objNr=%d w=%d h=%d bpc=%d buflen=%d\n", im.objNr, im.w, im.h, im.bpc, len(b))

	// Validate buflen.
	// Sometimes there is a trailing 0x0A in addition to the imagebytes.
	if len(b) < (3*im.bpc*im.w*im.h+7)/8 {
		return nil, errors.Errorf("writeDeviceRGBToPNG: objNr=%d corrupt image object\n", im.objNr)
	}

	// TODO Support bpc and decode.
	img := image.NewNRGBA(image.Rect(0, 0, im.w, im.h))

	i := 0
	for y := 0; y < im.h; y++ {
		for x := 0; x < im.w; x++ {
			alpha := uint8(255)
			if im.softMask != nil {
				alpha = im.softMask[y*im.w+x]
			}
			img.Set(x, y, color.NRGBA{R: b[i], G: b[i+1], B: b[i+2], A: alpha})
			i += 3
		}
	}

	return pngImgBuffer(img)
}

func ensureDeviceRGBCS(xRefTable *XRefTable, o Object) bool {

	o, err := xRefTable.Dereference(o)
	if err != nil {
		return false
	}

	switch altCS := o.(type) {
	case Name:
		return altCS == DeviceRGBCS
	}

	return false
}

func pngCalRGBBuffer(im *PDFImage) (*bytes.Buffer, error) {

	b := im.sd.Content

	log.Debug.Printf("writeCalRGBToPNG: objNr=%d w=%d h=%d bpc=%d buflen=%d\n", im.objNr, im.w, im.h, im.bpc, len(b))

	if len(b) < (3*im.bpc*im.w*im.h+7)/8 {
		return nil, errors.Errorf("writeCalRGBToPNG: objNr=%d corrupt image object %v\n", im.objNr, *im.sd)
	}

	// Optional int array "Range", length 2*N specifies min,max values of color components.
	// This information can be validated against the iccProfile.

	// RGB
	// TODO Support bpc, decode and softmask.
	img := image.NewNRGBA(image.Rect(0, 0, im.w, im.h))
	i := 0
	for y := 0; y < im.h; y++ {
		for x := 0; x < im.w; x++ {
			img.Set(x, y, color.NRGBA{R: b[i], G: b[i+1], B: b[i+2], A: 255})
			i += 3
		}
	}
	return pngImgBuffer(img)
}

func iccBasedBuffer(xRefTable *XRefTable, im *PDFImage, cs Array) (buf *bytes.Buffer, ext string, err error) {

	//  Any ICC profile >= ICC.1:2004:10 is sufficient for any PDF version <= 1.7
	//  If the embedded ICC profile version is newer than the one used by the Reader, substitute with Alternate color space.

	iccProfileStream, _ := xRefTable.DereferenceStreamDict(cs[1])

	b := im.sd.Content

	log.Debug.Printf("writeICCBasedToPNGFile: objNr=%d w=%d h=%d bpc=%d buflen=%d\n", im.objNr, im.w, im.h, im.bpc, len(b))

	// 1,3 or 4 color components.
	n := *iccProfileStream.IntEntry("N")

	if !IntMemberOf(n, []int{1, 3, 4}) {
		return nil, "", errors.Errorf("writeICCBasedToPNGFile: objNr=%d, N must be 1,3 or 4, got:%d\n", im.objNr, n)
	}

	// TODO: Transform linear XYZ to RGB according to ICC profile.
	// For now we fall back to appropriate color spaces for n
	// regardless of a specified alternate color space.

	// Validate buflen.
	// Sometimes there is a trailing 0x0A in addition to the imagebytes.
	if len(b) < (n*im.bpc*im.w*im.h+7)/8 {
		return nil, "", errors.Errorf("writeICCBased: objNr=%d corrupt image object %v\n", im.objNr, *im.sd)
	}

	switch n {
	case 1:
		// Gray
		buf, err = pngDeviceGrayBuffer(im)
		ext = pngExt

	case 3:
		// RGB
		buf, err = pngDeviceRGBBuffer(im)
		ext = pngExt

	case 4:
		// CMYK
		buf, err = tiffDeviceCMYKBuffer(im)
		ext = tiffExt
	}

	return buf, ext, err
}

func pngIndexedRGBBuffer(im *PDFImage, lookup []byte) (*bytes.Buffer, error) {

	b := im.sd.Content

	img := image.NewNRGBA(image.Rect(0, 0, im.w, im.h))

	// TODO handle decode.

	i := 0
	for y := 0; y < im.h; y++ {
		for x := 0; x < im.w; {
			p := b[i]
			for j := 0; j < 8/im.bpc; j++ {
				ind := p >> (8 - uint8(im.bpc))
				//fmt.Printf("x=%d y=%d i=%d j=%d p=#%02x ind=#%02x\n", x, y, i, j, p, ind)
				alpha := uint8(255)
				if im.softMask != nil {
					alpha = im.softMask[y*im.w+x]
				}
				l := 3 * int(ind)
				img.Set(x, y, color.NRGBA{R: lookup[l], G: lookup[l+1], B: lookup[l+2], A: alpha})
				p <<= uint8(im.bpc)
				x++
			}
			i++
		}
	}

	return pngImgBuffer(img)
}

func tiffIndexedCMYKBuffer(im *PDFImage, lookup []byte) (*bytes.Buffer, error) {

	b := im.sd.Content

	img := image.NewCMYK(image.Rect(0, 0, im.w, im.h))

	// TODO handle decode and softmask.

	i := 0
	for y := 0; y < im.h; y++ {
		for x := 0; x < im.w; {
			p := b[i]
			for j := 0; j < 8/im.bpc; j++ {
				ind := p >> (8 - uint8(im.bpc))
				//fmt.Printf("x=%d y=%d i=%d j=%d p=#%02x ind=#%02x\n", x, y, i, j, p, ind)
				l := 4 * int(ind)
				img.Set(x, y, color.CMYK{C: lookup[l], M: lookup[l+1], Y: lookup[l+2], K: lookup[l+3]})
				p <<= uint8(im.bpc)
				x++
			}
			i++
		}
	}

	return tiffImgBuffer(img)
}

func indexedNameCSBuffer(im *PDFImage, cs Name, maxInd int, lookup []byte) (*bytes.Buffer, string, error) {

	switch cs {

	case DeviceRGBCS:

		if len(lookup) < 3*(maxInd+1) {
			return nil, "", errors.Errorf("writeIndexedNameCS: objNr=%d, corrupt DeviceRGB lookup table\n", im.objNr)
		}

		buf, err := pngIndexedRGBBuffer(im, lookup)
		return buf, pngExt, err

	case DeviceCMYKCS:

		if len(lookup) < 4*(maxInd+1) {
			return nil, "", errors.Errorf("writeIndexedNameCS: objNr=%d, corrupt DeviceCMYK lookup table\n", im.objNr)
		}

		buf, err := tiffIndexedCMYKBuffer(im, lookup)
		return buf, tiffExt, err
	}

	log.Info.Printf("writeIndexedNameCS: objNr=%d, unsupported base colorspace %s\n", im.objNr, cs.String())

	return nil, "", ErrUnsupportedColorSpace
}

func indexedArrayCSBuffer(xRefTable *XRefTable, im *PDFImage, csa Array, maxInd int, lookup []byte) (*bytes.Buffer, string, error) {

	b := im.sd.Content

	cs, _ := csa[0].(Name)

	switch cs {

	case ICCBasedCS:

		iccProfileStream, _ := xRefTable.DereferenceStreamDict(csa[1])

		// 1,3 or 4 color components.
		n := *iccProfileStream.IntEntry("N")
		if !IntMemberOf(n, []int{1, 3, 4}) {
			return nil, "", errors.Errorf("writeIndexedArrayCS: objNr=%d, N must be 1,3 or 4, got:%d\n", im.objNr, n)
		}

		// Validate the lookup table.
		if len(lookup) < n*(maxInd+1) {
			return nil, "", errors.Errorf("writeIndexedArrayCS: objNr=%d, corrupt ICCBased lookup table\n", im.objNr)
		}

		// TODO: Transform linear XYZ to RGB according to ICC profile.
		// For now we fall back to approriate color spaces for n
		// regardless of a specified alternate color space.

		switch n {
		case 1:
			// Gray
			// TODO use lookupTable!
			// TODO handle bpc, decode and softmask.
			img := image.NewGray(image.Rect(0, 0, im.w, im.h))
			i := 0
			for y := 0; y < im.h; y++ {
				for x := 0; x < im.w; x++ {
					img.Set(x, y, color.Gray{Y: b[i]})
					i++
				}
			}
			buf, err := pngImgBuffer(img)
			return buf, pngExt, err

		case 3:
			// RGB
			buf, err := pngIndexedRGBBuffer(im, lookup)
			return buf, pngExt, err

		case 4:
			// CMYK
			log.Debug.Printf("writeIndexedArrayCS: CMYK objNr=%d w=%d h=%d bpc=%d buflen=%d\n", im.objNr, im.w, im.h, im.bpc, len(b))
			buf, err := tiffIndexedCMYKBuffer(im, lookup)
			return buf, tiffExt, err
		}
	}

	log.Info.Printf("writeIndexedArrayCS: objNr=%d, unsupported base colorspace %s\n", im.objNr, csa)

	return nil, "", ErrUnsupportedColorSpace
}

func indexedBuffer(xRefTable *XRefTable, im *PDFImage, cs Array) (*bytes.Buffer, string, error) {

	// Identify the base color space.
	baseCS, _ := xRefTable.Dereference(cs[1])

	// Identify the max index into the color lookup table.
	maxInd, _ := xRefTable.DereferenceInteger(cs[2])

	// Identify the color lookup table.
	var lookup []byte
	lookup, err := colorLookupTable(xRefTable, cs[3])
	if err != nil {
		return nil, "", err
	}
	if lookup == nil {
		return nil, "", errors.Errorf("writeIndexed: objNr=%d IndexedCS with corrupt lookup table %s\n", im.objNr, cs)
	}
	//fmt.Printf("lookup: \n%s\n", hex.Dump(l))

	b := im.sd.Content

	log.Debug.Printf("writeIndexed: objNr=%d w=%d h=%d bpc=%d buflen=%d maxInd=%d\n", im.objNr, im.w, im.h, im.bpc, len(b), maxInd)

	// Validate buflen.
	// The image data is a sequence of index values for pixels.
	// Sometimes there is a trailing 0x0A.
	if len(b) < (im.bpc*im.w*im.h+7)/8 {
		return nil, "", errors.Errorf("writeIndexed: objNr=%d corrupt image object %v\n", im.objNr, *im.sd)
	}

	switch cs := baseCS.(type) {
	case Name:
		return indexedNameCSBuffer(im, cs, maxInd.Value(), lookup)

	case Array:
		return indexedArrayCSBuffer(xRefTable, im, cs, maxInd.Value(), lookup)
	}

	return nil, "", nil
}

func flateEncodedImageBuffer(xRefTable *XRefTable, sd *StreamDict, objNr int) (buf *bytes.Buffer, ext string, err error) {

	pdfImage, err := pdfImage(xRefTable, sd, objNr)
	if err != nil {
		return nil, "", err
	}

	o, err := xRefTable.DereferenceDictEntry(sd.Dict, "ColorSpace")
	if err != nil {
		return nil, "", err
	}

	switch cs := o.(type) {

	case Name:
		switch cs {

		case DeviceGrayCS:
			buf, err = pngDeviceGrayBuffer(pdfImage)
			ext = pngExt

		case DeviceRGBCS:
			buf, err = pngDeviceRGBBuffer(pdfImage)
			ext = pngExt

		case DeviceCMYKCS:
			buf, err = tiffDeviceCMYKBuffer(pdfImage)
			ext = tiffExt

		default:
			log.Info.Printf("writeFlateEncodedImage: objNr=%d, unsupported name colorspace %s\n", objNr, cs.String())
			err = ErrUnsupportedColorSpace
		}

	case Array:
		csn, _ := cs[0].(Name)

		switch csn {

		case CalRGBCS:
			buf, err = pngCalRGBBuffer(pdfImage)
			ext = pngExt

		case ICCBasedCS:
			buf, ext, err = iccBasedBuffer(xRefTable, pdfImage, cs)

		case IndexedCS:
			buf, ext, err = indexedBuffer(xRefTable, pdfImage, cs)

		default:
			log.Info.Printf("writeFlateEncodedImage: objNr=%d, unsupported array colorspace %s\n", objNr, csn)
			err = ErrUnsupportedColorSpace

		}

	}

	return buf, ext, err
}

// WriteImage writes a PDF image object to disk.
func WriteImage(xRefTable *XRefTable, filename string, sd *StreamDict, objNr int) (string, error) {
	buf, ext, err := ImageBuffer(xRefTable, sd, objNr)
	if err != nil {
		return "", err
	}

	fn := filename + ext
	f, err := os.OpenFile(fn, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return fn, err
	}

	_, err = io.Copy(f, buf)
	if err1 := f.Close(); err == nil {
		err = err1
	}

	return fn, err
}

// ImageBuffer converts a PDF image to a bytes.Buffer and returns it with its extension.
func ImageBuffer(xRefTable *XRefTable, sd *StreamDict, objNr int) (buf *bytes.Buffer, ext string, err error) {

	switch sd.FilterPipeline[0].Name {

	case filter.Flate, filter.CCITTFax:
		// If color space is CMYK then write .tif else write .png
		buf, ext, err := flateEncodedImageBuffer(xRefTable, sd, objNr)
		if err != nil {
			if err == ErrUnsupportedColorSpace {
				log.Info.Printf("Image obj#%d uses an unsupported color space. Please see the logfile for details.\n", objNr)
				err = nil
			}
		}
		return buf, ext, err

	case filter.DCT:
		return bytes.NewBuffer(sd.Raw), jpgExt, nil
	case filter.JPX:
		return bytes.NewBuffer(sd.Raw), jpxExt, nil
	}

	err = fmt.Errorf("unknown image filter")
	return
}
